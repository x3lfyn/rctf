package controller

import (
	"regexp"
	"testing"

	rctfv1 "github.com/otter-sec/rctf/api/v1"
	"github.com/traefik/traefik/v2/pkg/provider/kubernetes/crd/traefikio/v1alpha1"
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

func TestExposeToObjectsExternalTLSTermination(t *testing.T) {
	exposeFor := func(kind rctfv1.ExposeType) rctfv1.ChallengeInstanceExpose {
		return rctfv1.ChallengeInstanceExpose{
			Kind:          kind,
			HostPrefix:    "app",
			ContainerName: "app",
			ContainerPort: 8080,
		}
	}

	httpEntryPoints := func(t *testing.T, external bool) map[string]bool {
		t.Helper()
		objects := exposeToObjects(&rctfv1.ChallengeInstance{}, exposeFor(rctfv1.HTTP), "app.example.com", external)
		if len(objects) != 1 {
			t.Fatalf("expected 1 object for http expose, got %d", len(objects))
		}
		route, ok := objects[0].(*v1alpha1.IngressRoute)
		if !ok {
			t.Fatalf("expected an IngressRoute, got %T", objects[0])
		}
		entryPoints := map[string]bool{}
		for _, ep := range route.Spec.EntryPoints {
			entryPoints[ep] = true
		}
		return entryPoints
	}

	t.Run("default mode serves http exposes on web only", func(t *testing.T) {
		entryPoints := httpEntryPoints(t, false)
		if !entryPoints["web"] || entryPoints["websecure"] {
			t.Fatalf("expected only the web entrypoint, got %v", entryPoints)
		}
	})

	t.Run("external mode serves http exposes on web and websecure", func(t *testing.T) {
		entryPoints := httpEntryPoints(t, true)
		if !entryPoints["web"] || !entryPoints["websecure"] {
			t.Fatalf("expected web and websecure entrypoints, got %v", entryPoints)
		}
	})

	t.Run("default mode creates redirect middleware for https exposes", func(t *testing.T) {
		objects := exposeToObjects(&rctfv1.ChallengeInstance{}, exposeFor(rctfv1.HTTPS), "app.example.com", false)
		if len(objects) != 3 {
			t.Fatalf("expected 3 objects for https expose in default mode, got %d", len(objects))
		}
		route, ok := objects[2].(*v1alpha1.IngressRoute)
		if !ok {
			t.Fatalf("expected an IngressRoute, got %T", objects[2])
		}
		if len(route.Spec.EntryPoints) != 1 || route.Spec.EntryPoints[0] != "websecure" {
			t.Fatalf("expected the https route on websecure only, got %v", route.Spec.EntryPoints)
		}
	})

	t.Run("external mode serves https exposes on both entrypoints without redirects", func(t *testing.T) {
		objects := exposeToObjects(&rctfv1.ChallengeInstance{}, exposeFor(rctfv1.HTTPS), "app.example.com", true)
		if len(objects) != 1 {
			t.Fatalf("expected 1 object for https expose in external mode, got %d", len(objects))
		}
		route, ok := objects[0].(*v1alpha1.IngressRoute)
		if !ok {
			t.Fatalf("expected an IngressRoute, got %T", objects[0])
		}
		entryPoints := map[string]bool{}
		for _, ep := range route.Spec.EntryPoints {
			entryPoints[ep] = true
		}
		if !entryPoints["web"] || !entryPoints["websecure"] {
			t.Fatalf("expected web and websecure entrypoints, got %v", entryPoints)
		}
	})
}
