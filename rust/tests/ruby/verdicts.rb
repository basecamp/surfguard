# frozen_string_literal: true

# Writes the gem's own verdicts for a deterministic corpus of addresses,
# hosts and URLs, which tests/ruby_parity.rs replays against the crate. The
# shared conformance corpus pins the cases someone thought of; this pins the
# gem itself, edges and random spellings included, so the two cannot drift
# where nobody looked.
#
#   ruby rust/tests/ruby/verdicts.rb > verdicts.json
#   SURFGUARD_RUBY_VERDICTS=verdicts.json cargo test --test ruby_parity
#
# Run on Linux: the gem reads numeric hosts with glibc's getaddrinfo, which
# is the grammar the crate implements.

require "ipaddr"
require "json"
require "resolv"
require_relative "../../../lib/surfguard"

PUBLIC = "93.184.216.34"
POLICIES = %i[default iana_special_use].freeze

def last_address(range)
  range.to_range.end
end

def neighbours(range)
  first = range.to_range.begin
  last = last_address(range)
  bits = range.ipv4? ? 32 : 128
  family = range.family
  points = [ first, last ]
  points << IPAddr.new(first.to_i - 1, family) if first.to_i.positive?
  points << IPAddr.new(last.to_i + 1, family) if last.to_i < (1 << bits) - 1
  points
end

tables = Surfguard::IANA_ALLOCATED_IPV6_UNICAST + Surfguard::DISALLOWED_IPV4 + Surfguard::DISALLOWED_IPV6 +
  Surfguard::IANA_SPECIAL_USE_IPV4 + Surfguard::IANA_SPECIAL_USE_IPV6 +
  Surfguard::GLOBALLY_REACHABLE_IETF_ASSIGNMENTS +
  [ Surfguard::IETF_PROTOCOL_ASSIGNMENTS, Surfguard::NAT64_WELL_KNOWN, Surfguard::NAT64_LOCAL_USE,
    Surfguard::IPV4_TRANSLATABLE, Surfguard::IPV4_COMPATIBLE, IPAddr.new("::ffff:0:0/96"),
    IPAddr.new("fc00::/7"), IPAddr.new("fe80::/10"), IPAddr.new("::1/128") ]
edges = tables.flat_map { |range| neighbours(range) }

random = Random.new(Integer(ENV.fetch("SURFGUARD_VERDICTS_SEED", "0x53555246")))
ipv4_edges = edges.select(&:ipv4?)
embedded = (ipv4_edges + 2_000.times.map { IPAddr.new(random.rand(1 << 32), Socket::AF_INET) }).flat_map do |ipv4|
  [ Surfguard::NAT64_WELL_KNOWN, Surfguard::IPV4_TRANSLATABLE, IPAddr.new("::ffff:0:0/96"), Surfguard::IPV4_COMPATIBLE ]
    .map { |prefix| IPAddr.new(prefix.to_i | ipv4.to_i, Socket::AF_INET6) }
end
random_addresses = 20_000.times.map do |index|
  family = index.even? ? Socket::AF_INET : Socket::AF_INET6
  IPAddr.new(random.rand(1 << (family == Socket::AF_INET ? 32 : 128)), family)
end
canonical = (edges + embedded + random_addresses).map(&:to_s).uniq

def spellings(address)
  ip = IPAddr.new(address)
  if ip.ipv4?
    octets = address.split(".")
    [ "#{address}/32", "#{address}/255.255.255.255", "#{address}/31", "#{address}/032", "[#{address}]",
      "#{address}/255.255.255.255/32", "#{address}/255.255.255.255/255.255.255.255/31",
      octets.map { |octet| octet.rjust(3, "0") }.join("."), "::ffff:#{address}", "::#{address}" ]
  else
    full = ip.to_string
    [ "[#{address}]", "#{address}/128", "#{address}/127", "[#{address}]/128", address.upcase, full,
      "#{address}%eth0", "#{full}/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
      "#{address}/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "#{address}/[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/127" ]
  end
end

ADDRESS_ALPHABET = "0123456789abcdefABCDEFxX.:/[]% -".chars.freeze
def noise(random, alphabet, longest)
  Array.new(random.rand(1..longest)) { alphabet[random.rand(alphabet.length)] }.join
end

address_inputs = (canonical + canonical.first(4_000).flat_map { |address| spellings(address) } +
  5_000.times.map { noise(random, ADDRESS_ALPHABET, 24) } +
  %w[::2:3:4:5:6:1.2.3.4 1::2:3:4:5:1.2.3.4 1:2:3:4:5:6:7:: ::1:2:3:4:5:6:7 1:2:3:4:5:6:7::8 01.2.3.4 1.2.3 2130706433]).uniq

addresses = address_inputs.map do |input|
  verdicts = POLICIES.to_h { |policy| [ policy.to_s, Surfguard.blocked_address?(input, policy: policy) ] }
  { "input" => input }.merge(verdicts)
end

def legacy_spellings(random, ip)
  value = ip.to_i
  octets = ip.to_s.split(".").map(&:to_i)
  part = lambda do |number|
    case random.rand(3)
    when 0 then number.to_s
    when 1 then "0x#{number.to_s(16)}"
    else number.zero? ? "0" : "0#{number.to_s(8)}"
    end
  end
  [ value.to_s, "0x#{value.to_s(16)}", "0X#{value.to_s(16).upcase}", "0#{value.to_s(8)}",
    "#{part.call(octets[0])}.#{part.call(value & 0xff_ffff)}",
    "#{part.call(octets[0])}.#{part.call(octets[1])}.#{part.call(value & 0xffff)}",
    octets.map { |octet| part.call(octet) }.join("."),
    "#{octets[0]}.#{octets[1]}.#{octets[2]}.#{octets[3] + 256}", "#{value + (1 << 32)}" ]
end

def decorations(host)
  [ "#{host}.", ".#{host}", "#{host}..", "/#{host}", "//#{host}", "#{host}/32", "#{host}/24", "#{host}%lo",
    host.sub(".", ".."), "[#{host}]", "#{host}.example", "x#{host}", "#{host}x" ]
end

HOST_ALPHABET = "0123456789abcdefxX.-_:/[]%".chars.freeze
names = %w[example.com example.com. a.b.c xn--bcher-kva.example localhost 123.example 0x7f000001.example
  1.2.3.4.5 a_b.1.1.1.1.sslip.io -a.example a-.example a--b.example] +
  [ "#{"a" * 63}.example", "#{"a" * 64}.example", "#{"a." * 127}a", "#{"a." * 127}ab", "a" * 255, "a" * 256 ]
legacy = (ipv4_edges.first(400) + 600.times.map { IPAddr.new(random.rand(1 << 32), Socket::AF_INET) })
  .flat_map { |ip| legacy_spellings(random, ip) }
host_inputs = (names + legacy + legacy.first(1_500).flat_map { |host| decorations(host) } +
  names.flat_map { |host| decorations(host) } + canonical.first(1_000) +
  canonical.first(1_000).flat_map { |address| spellings(address) } +
  5_000.times.map { noise(random, HOST_ALPHABET, 20) }).uniq

def with_dns
  asked = []
  original = Resolv.method(:getaddresses)
  Resolv.define_singleton_method(:getaddresses) do |host|
    asked << host
    [ PUBLIC ]
  end
  [ yield, asked ]
ensure
  Resolv.define_singleton_method(:getaddresses, original)
end

def outcome
  yield
rescue Surfguard::Unresolvable
  "unresolvable"
rescue Surfguard::Violation => violation
  violation.message
rescue StandardError => error
  "raises #{error.class}"
end

hosts = host_inputs.map do |input|
  result, asked = with_dns { outcome { Surfguard.resolve_public_ips(input) } }
  { "input" => input, "result" => result, "asked" => asked }
end

URL_ALPHABET = "abcx019.-_~:/?#[]@!$&'()*+,;=% \t".chars.freeze
url_hosts = [
  "example.com", "93.184.216.34", "10.0.0.1", "[::1]", "[2606:2800:220:1:248:1893:25c8:1946]", "[v1.fe]",
  "[V1.fe]", "[fe80::1%25lo]", "2130706433", "0x7f.1", "a_b.example", "%31%32%37.0.0.1", "example.com.",
  "[::ffff:1.2.3.4]", "[1.2.3.4]", "[::2:3:4:5:6:1.2.3.4]", "168.63.129.16", "localhost", "LOCALHOST"
] + host_inputs.first(300)
url_shapes = [
  ->(host) { "https://#{host}/" }, ->(host) { "http://#{host}" }, ->(host) { "//#{host}/path" },
  ->(host) { "https://user:pass@#{host}:8443/a/b?c=d#e" }, ->(host) { "https://#{host}:/" },
  ->(host) { "https://#{host}:abc/" }, ->(host) { "https://#{host}/?q=%zz" }, ->(host) { "https://#{host}/#%zz" },
  ->(host) { "https://#{host}/%zz" }, ->(host) { "https://#{host}/a b" }, ->(host) { "https://#{host}/?a b" },
  ->(host) { "file://#{host}/x" }, ->(host) { "FILE://#{host}/x" }, ->(host) { "ldap://#{host}/x#f" },
  ->(host) { "ldap://#{host}/x?y" }, ->(host) { "mailto://#{host}?subject=x" }, ->(host) { "mailto://#{host}" }, ->(host) { "ftp://#{host}/a;type=i" },
  ->(host) { "ws://#{host}/" }, ->(host) { "x-y.z+w://#{host}/" }, ->(host) { "1http://#{host}/" },
  ->(host) { "https:#{host}" }, ->(host) { "https:/#{host}" }, ->(host) { " https://#{host}/" },
  ->(host) { "https://#{host}/\n" }, ->(host) { "https://a@b@#{host}/" }, ->(host) { "https://#{host}?x#y" }
]
url_inputs = (url_hosts.product(url_shapes).map { |host, shape| shape.call(host) } +
  [ "https://", "http://", "https:///path", "::::not a url", "example.com", "mailto:a@example.com",
    "https://[::1", "https://::1/" ] +
  5_000.times.map { "https://#{noise(random, URL_ALPHABET, 16)}" } +
  5_000.times.map { noise(random, URL_ALPHABET, 24) }).uniq

urls = url_inputs.map do |input|
  (single, enforce), asked = with_dns do
    [ outcome { Surfguard.resolve_public_ip(input) }, outcome { Surfguard.enforce_public_ip(input) || "ok" } ]
  end
  { "input" => input, "single" => single, "enforce" => enforce, "asked" => asked.uniq }
end

puts JSON.generate(
  "surfguard" => Surfguard::VERSION, "ruby" => RUBY_VERSION,
  "addresses" => addresses, "hosts" => hosts, "urls" => urls
)
