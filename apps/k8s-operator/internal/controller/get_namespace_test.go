package controller

import (
	"regexp"
	"testing"

	rctfv1 "github.com/otter-sec/rctf/api/v1"
)

var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func TestGetNamespaceForInstance(t *testing.T) {
	instanceFor := func(challengeId, teamId string) *rctfv1.ChallengeInstance {
		return &rctfv1.ChallengeInstance{
			Spec: rctfv1.ChallengeInstanceSpec{
				ChallengeId: challengeId,
				TeamId:      teamId,
			},
		}
	}

	t.Run("short ids are used verbatim", func(t *testing.T) {
		instance := instanceFor("SmOkEtEsT", "TeAm")
		got := getNamespaceForInstance(instance)
		if got != "inst-smoketest-team" {
			t.Fatalf("expected inst-smoketest-team, got %q", got)
		}
	})

	t.Run("uuid ids fit in 63 characters", func(t *testing.T) {
		instance := instanceFor("ce1c0eb0-04cb-4fad-ad23-d6194114a635", "0b44b0a7-4121-4624-bf96-5df7e185e5dd")
		got := getNamespaceForInstance(instance)
		if len(got) != 63 {
			t.Fatalf("expected 63 characters, got %d (%q)", len(got), got)
		}
		if !dns1123Label.MatchString(got) {
			t.Fatalf("expected a valid DNS-1123 label, got %q", got)
		}
	})

	t.Run("truncated names are deterministic and collision-resistant", func(t *testing.T) {
		instance := instanceFor("ce1c0eb0-04cb-4fad-ad23-d6194114a635", "0b44b0a7-4121-4624-bf96-5df7e185e5dd")
		first := getNamespaceForInstance(instance)
		second := getNamespaceForInstance(instance)
		if first != second {
			t.Fatalf("expected deterministic name, got %q and %q", first, second)
		}

		other := getNamespaceForInstance(instanceFor("ce1c0eb0-04cb-4fad-ad23-d6194114a636", "0b44b0a7-4121-4624-bf96-5df7e185e5dd"))
		if other == first {
			t.Fatalf("expected different names for different ids, both are %q", first)
		}
	})
}
