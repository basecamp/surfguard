package surfguard

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestViolationMessagesAreFixedAndNonLeaking(t *testing.T) {
	messages := map[Reason]string{
		ReasonBlockedAddr:       "surfguard: refusing blocked address",
		ReasonMalformedHost:     "surfguard: refusing malformed address",
		ReasonNetwork:           "surfguard: refusing non-TCP network",
		ReasonPort:              "surfguard: refusing blocked port",
		ReasonScheme:            "surfguard: refusing unsupported scheme",
		ReasonRedirectDowngrade: "surfguard: refusing redirect scheme downgrade",
		ReasonTooManyRedirects:  "surfguard: refusing to follow more redirects",
	}
	for reason, want := range messages {
		violation := &Violation{
			Host:   "attacker-controlled-host.example",
			Addr:   netip.MustParseAddr("10.11.12.13"),
			Port:   4443,
			Reason: reason,
		}
		if violation.Error() != want {
			t.Errorf("%v: got %q, want %q", reason, violation.Error(), want)
		}
		for _, leak := range []string{"attacker", "10.11.12.13", "4443"} {
			if strings.Contains(violation.Error(), leak) {
				t.Errorf("%v: message leaks %q", reason, leak)
			}
		}
	}
	if (&Violation{Reason: Reason(99)}).Error() != "surfguard: refusing blocked address" {
		t.Error("unknown reasons fall back to the blocked-address message")
	}
}

func TestReasonStrings(t *testing.T) {
	names := map[Reason]string{
		ReasonBlockedAddr:       "blocked-address",
		ReasonMalformedHost:     "malformed-host",
		ReasonNetwork:           "network",
		ReasonPort:              "port",
		ReasonScheme:            "scheme",
		ReasonRedirectDowngrade: "redirect-downgrade",
		ReasonTooManyRedirects:  "too-many-redirects",
		Reason(99):              "blocked-address",
	}
	for reason, want := range names {
		if reason.String() != want {
			t.Errorf("%d.String() = %q, want %q", int(reason), reason.String(), want)
		}
	}
}

func TestErrorFamilies(t *testing.T) {
	violation := &Violation{Reason: ReasonPort}
	if !errors.Is(violation, ErrBlocked) {
		t.Error("every Violation is in the ErrBlocked family")
	}
	if errors.Is(violation, ErrUnresolvable) {
		t.Error("Violation must not match ErrUnresolvable")
	}

	unresolvable := &UnresolvableError{Host: "target.example"}
	if !errors.Is(unresolvable, ErrUnresolvable) {
		t.Error("UnresolvableError is in the ErrUnresolvable family")
	}
	if errors.Is(unresolvable, ErrBlocked) {
		t.Error("UnresolvableError must not match ErrBlocked: retry vs deactivate")
	}
}

func TestUnresolvableWrappingKeepsTheMessageFixed(t *testing.T) {
	inner := fmt.Errorf("lookup burst: %s", "attacker-controlled detail")
	err := &UnresolvableError{Host: "target.example", Err: inner}
	if err.Error() != "surfguard: host could not be resolved" {
		t.Errorf("got %q", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Error("the underlying error stays reachable for structured handling")
	}
	if strings.Contains(err.Error(), "attacker") {
		t.Error("the message must never include the wrapped error")
	}
	wrapped := fmt.Errorf("fetch: %w", err)
	if !errors.Is(wrapped, ErrUnresolvable) {
		t.Error("family survives further wrapping")
	}
}

// A Resolver is caller-supplied code, so one may apply its own policy and
// return ErrBlocked. Carrying that into this chain would make a single error
// match both families and collapse retry-versus-deactivate, so the cause is
// dropped from the chain — but kept on the field.
func TestAResolverCauseCannotDragErrBlockedIntoTheUnresolvableFamily(t *testing.T) {
	for label, cause := range map[string]error{
		"the sentinel itself": ErrBlocked,
		"a wrapped sentinel":  fmt.Errorf("resolver policy: %w", ErrBlocked),
		"a Violation":         &Violation{Host: "target.example", Reason: ReasonBlockedAddr},
	} {
		err := &UnresolvableError{Host: "target.example", Err: cause}
		if !errors.Is(err, ErrUnresolvable) {
			t.Errorf("%s: must stay unresolvable, got %v", label, err)
		}
		if errors.Is(err, ErrBlocked) {
			t.Errorf("%s: must not join the blocked family — a failed lookup is not a refusal", label)
		}
		if err.Err != cause {
			t.Errorf("%s: the cause must stay reachable on the field", label)
		}
		if err.Error() != ErrUnresolvable.Error() {
			t.Errorf("%s: message must stay fixed, got %q", label, err.Error())
		}
	}

	// An ordinary cause is still part of the chain.
	inner := errors.New("i/o timeout")
	if err := (&UnresolvableError{Err: inner}); !errors.Is(err, inner) {
		t.Error("an ordinary resolver cause must stay reachable through errors.Is")
	}
}
