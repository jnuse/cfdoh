package pool

import (
	"path/filepath"
	"testing"
)

// The content tag is the cache-key answer to pool flips (F-004/F-007/F-028):
// any content change must change it, no-op re-reports must not, and it must
// survive a snapshot save/reload so restarts keep cached answers valid.

func TestContentTagFlipsOnPoolMutation(t *testing.T) {
	resetPool(t, 1_000_000)
	empty := ContentTag()

	if err := SetLearned([]string{"104.17.9.1"}, nil, 3600, "probe-a", ""); err != nil {
		t.Fatal(err)
	}
	first := ContentTag()
	if first == empty {
		t.Fatal("uploading a default pool must change the content tag")
	}

	// identical re-report with only a refreshed TTL: no content flip
	if err := SetLearned([]string{"104.17.9.1"}, nil, 7200, "probe-a", ""); err != nil {
		t.Fatal(err)
	}
	if got := ContentTag(); got != first {
		t.Fatalf("identical re-report changed the tag: %s -> %s", first, got)
	}

	// same key, new addresses: a same-scope content flip
	if err := SetLearned([]string{"104.17.9.2"}, nil, 3600, "probe-a", ""); err != nil {
		t.Fatal(err)
	}
	flipped := ContentTag()
	if flipped == first {
		t.Fatal("a pool content flip must change the content tag")
	}

	// github and site pool writes flip it too
	SetGithub("probe-a", map[string][]string{"git.example": {"104.16.9.9"}}, 3600)
	withGithub := ContentTag()
	if withGithub == flipped {
		t.Fatal("a github pool write must change the content tag")
	}
	SetSites("probe-a", map[string][]string{"site.example": {"104.16.9.8"}}, 3600)
	if got := ContentTag(); got == withGithub {
		t.Fatal("a site pool write must change the content tag")
	}

	// a second learned source with identical content is still a change
	if err := SetLearned([]string{"104.17.9.2"}, nil, 3600, "probe-b", ""); err != nil {
		t.Fatal(err)
	}
	if got := ContentTag(); got == withGithub {
		t.Fatal("adding a source must change the content tag")
	}
}

// The hub feed rewrites every adopted scope each cycle by iterating a
// map, so the write order of identical per-scope content varies per
// refresh; the tag must depend on content only, never on that order
// (C1/M1).
func TestContentTagStableAcrossScopeRewriteOrder(t *testing.T) {
	resetPool(t, 1_000_000)
	content := map[string]string{"isp:chinanet": "104.17.9.1", "isp:unicom": "104.17.9.2"}
	write := func(order ...string) {
		for _, scope := range order {
			if err := SetLearned([]string{content[scope]}, nil, 1800, "pool-feed", scope); err != nil {
				t.Fatal(err)
			}
		}
	}
	write("isp:chinanet", "isp:unicom")
	first := ContentTag()

	// periodic refresh of identical content in the opposite write order
	write("isp:unicom", "isp:chinanet")
	if got := ContentTag(); got != first {
		t.Fatalf("identical content rewritten in a different scope order changed the tag: %s -> %s", first, got)
	}

	// and from a clean table the write order alone must not set the tag
	resetPool(t, 1_000_000)
	write("isp:unicom", "isp:chinanet")
	if got := ContentTag(); got != first {
		t.Fatalf("tag depends on write order: %s -> %s", first, got)
	}
}

func TestContentTagStableAcrossStateReload(t *testing.T) {
	resetPool(t, 1_000_000)
	if err := SetLearned([]string{"104.17.9.1"}, nil, 3600, "probe-a", ""); err != nil {
		t.Fatal(err)
	}
	if err := SetLearned([]string{"104.17.9.3"}, nil, 3600, "hub", "isp:chinanet"); err != nil {
		t.Fatal(err)
	}
	SetSites("probe-a", map[string][]string{"site.example": {"104.16.9.8"}}, 3600)
	before := ContentTag()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveState(path); err != nil {
		t.Fatal(err)
	}
	resetPool(t, 1_000_000) // wipe: same clock base, fresh tables
	if err := LoadState(path); err != nil {
		t.Fatal(err)
	}
	if after := ContentTag(); after != before {
		t.Fatalf("content tag changed across snapshot reload: %s -> %s", before, after)
	}
}

func TestContentTagExpiresWithLastPool(t *testing.T) {
	resetPool(t, 1_000_000)
	empty := ContentTag()

	if err := SetLearned([]string{"104.17.9.1"}, nil, 60, "probe-a", ""); err != nil {
		t.Fatal(err)
	}
	withPool := ContentTag()
	if withPool == empty {
		t.Fatal("uploading a pool must change the content tag")
	}

	now = func() int64 { return 1_000_000 + 61_000 } // past the ttl=60 entry
	if got := ContentTag(); got == withPool {
		t.Fatal("the tag must change when the last pool entry expires (layer fallback, F-007)")
	}
	if got := ContentTag(); got != empty {
		t.Fatalf("expired-everything tag = %s, want the all-empty tag %s", got, empty)
	}
}
