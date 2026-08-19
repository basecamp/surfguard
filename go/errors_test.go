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
