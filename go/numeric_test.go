package surfguard

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

func TestParseLegacyIPv4KnownSpellings(t *testing.T) {
	cases := map[string]string{
		"2130706433":          "127.0.0.1",
		"127.1":               "127.0.0.1",
		"127.0.1":             "127.0.0.1",
		"0x7f000001":          "127.0.0.1",
		"0x7f.1":              "127.0.0.1",
		"0177.0.0.01":         "127.0.0.1",
		"0":                   "0.0.0.0",
		"00":                  "0.0.0.0",
		"0x0":                 "0.0.0.0",
		"2852039166":          "169.254.169.254",
		"0xa9fea9fe":          "169.254.169.254",
		"0251.0376.0251.0376": "169.254.169.254",
		"1572395042":          "93.184.216.34",
		"169.254.43518":       "169.254.169.254",
		"127.11534337":        "127.176.0.1",
		"4294967295":          "255.255.255.255",
		"0xffffffff":          "255.255.255.255",
		"037777777777":        "255.255.255.255",
		"93.184.216.34":       "93.184.216.34",
	}
	for input, want := range cases {
		addr, ok := parseLegacyIPv4(input)
		if !ok || addr != netip.MustParseAddr(want) {
			t.Errorf("parseLegacyIPv4(%q) = %v, %v; want %s", input, addr, ok, want)
		}
	}
}

func TestParseLegacyIPv4Refusals(t *testing.T) {
	for _, input := range []string{
		"", ".", "1.2.3.4.5", "256.0.0.1", "1.2.3.256", "1.16777216", "1.2.65536",
		"1.2.3.4.", ".1.2.3.4", "1..2", "08", "0182", "0x", "0xg", "4294967296",
		"0x100000000", "040000000000", "127.0.0.0x", "1.2.3.-4", "+1.2.3.4",
		"1_0", "0x_7f", " 127.0.0.1", "127.0.0.1 ", "example.com", "127.0.0.1/32",
	} {
		if addr, ok := parseLegacyIPv4(input); ok {
			t.Errorf("parseLegacyIPv4(%q) accepted %s; must refuse", input, addr)
		}
	}
}

// Differential: for canonical dotted-quad spellings the legacy parser and
// netip.ParseAddr must agree exactly, and every legacy spelling of a random
// address must decode to that address.
func TestLegacyParserDifferentialAgainstNetip(t *testing.T) {
	random := rand.New(rand.NewSource(0x4c454741))
	for i := 0; i < 5000; i++ {
		var raw [4]byte
		random.Read(raw[:])
		addr := netip.AddrFrom4(raw)
		canonical := addr.String()
		got, ok := parseLegacyIPv4(canonical)
		if !ok || got != addr {
			t.Fatalf("canonical %q: got %v, %v", canonical, got, ok)
		}
		value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		spellings := []string{
			fmt.Sprintf("%d", value),
			fmt.Sprintf("0x%x", value),
			fmt.Sprintf("0X%X", value),
			fmt.Sprintf("0%o", value),
			fmt.Sprintf("%d.%d", raw[0], value&0x00ffffff),
			fmt.Sprintf("%d.%d.%d", raw[0], raw[1], value&0x0000ffff),
			fmt.Sprintf("0x%x.0x%x.0x%x.0x%x", raw[0], raw[1], raw[2], raw[3]),
		}
		for _, spelling := range spellings {
			got, ok := parseLegacyIPv4(spelling)
			if !ok || got != addr {
				t.Fatalf("%q (for %s): got %v, %v", spelling, addr, got, ok)
			}
		}
	}
}

func TestClassifyHostKinds(t *testing.T) {
	literals := map[string]string{
		"127.0.0.1":              "127.0.0.1",
		"2130706433":             "127.0.0.1",
		"127.1":                  "127.0.0.1",
		"::1":                    "::1",
		"64:ff9b::1":             "64:ff9b::1",
		"93.184.216.34/32":       "93.184.216.34",
		"::1/128":                "::1",
		"::ffff:169.254.169.254": "::ffff:169.254.169.254",
	}
	for input, want := range literals {
		kind, addr := classifyHost(input)
		if kind != hostLiteral || addr != netip.MustParseAddr(want) {
			t.Errorf("classifyHost(%q) = %v, %v; want literal %s", input, kind, addr, want)
		}
	}

	hostnames := []string{
		"example.com", "example.com.", "a", "0xfoo.example", "1.2.3.4.5",
		"127.0.0.1.example", "xn--nxasmq6b.example", "a-b.c-d",
	}
	for _, input := range hostnames {
		if kind, _ := classifyHost(input); kind != hostName {
			t.Errorf("classifyHost(%q) = %v; want hostname", input, kind)
		}
	}

	malformed := []string{
		"127.0.0.1.", "08", "0182", "300.1.2.3", "4294967296", "not:a:valid:ipv6",
		"[::1]", "::1/64", "10.0.0.1/8", "example..com", "-a.example",
		"a-.example", "a_b.example", ".", "..", "2606:2800:220:1:248:1893:25c8:1946/64",
	}
	for _, input := range malformed {
		if kind, _ := classifyHost(input); kind != hostMalformed {
			t.Errorf("classifyHost(%q) = %v; want malformed", input, kind)
		}
	}
}

func TestClassifyHostLegacyShapedFailuresNeverBecomeHostnames(t *testing.T) {
	// "08" and friends are refused as malformed even though the octal parse
	// fails: a legacy-shaped token must never fall through to DNS where a
	// wildcard could answer for it.
	for _, input := range []string{"08", "09", "0182", "300", "256.1"} {
		kind, _ := classifyHost(input)
		if kind == hostName {
			t.Errorf("classifyHost(%q) fell through to DNS", input)
		}
	}
	// "0x1g" has a non-hex byte in a hex component, so it is not
	// legacy-shaped at all; it must be judged by hostname grammar instead
	// (and LDH admits it — DNS labels may look like anything alphanumeric).
	if kind, _ := classifyHost("0x1g"); kind != hostName {
		t.Errorf("classifyHost(0x1g) = %v; LDH admits alphanumeric labels", kind)
	}
}

func TestNormalizeHostBounds(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	refused := []string{
		"", string(long), "example\x00.com", "café.example",
		"127.0.0.1%lo", "fe80::1%eth0", "%",
	}
	for _, host := range refused {
		if _, err := normalizeHost(host); err == nil {
			t.Errorf("normalizeHost(%q) accepted", host)
		}
	}
	ok := string(long[:255])
	if _, err := normalizeHost(ok); err != nil {
		t.Errorf("normalizeHost rejected a 255-byte host: %v", err)
	}
}
