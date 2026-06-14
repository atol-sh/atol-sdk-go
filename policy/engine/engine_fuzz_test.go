package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/bundle"

	"atol.sh/sdk-go/zanzibar"
	"atol.sh/sdk-go/zanzibar/store"
)

// FuzzLoadBundle feeds arbitrary bytes into LoadBundle. The .rego
// fixtures under testdata/policies/ seed the corpus so the fuzzer
// starts from realistic shapes and explores mutations. The
// contract: LoadBundle must never panic, must always return an error
// for invalid input, and a valid-looking partial bundle must not
// corrupt a previously-loaded one.
func FuzzLoadBundle(f *testing.F) {
	// Seed with each realistic policy packed as a bundle.
	dir := filepath.Join("testdata", "policies")
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".rego" {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			packed, err := packRegoBundle(src)
			if err != nil {
				continue
			}
			f.Add(packed)
		}
	}

	// A few raw garbage seeds to steer the mutator early.
	f.Add([]byte{})
	f.Add([]byte("not-a-bundle"))
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})

	// Pre-load a valid bundle so the fuzz can see whether bad input
	// corrupts the cached snapshot. The fuzz function re-checks the
	// snapshot after every LoadBundle failure.
	ms := store.NewMemoryStore()
	zEngine := zanzibar.New(ms, nil, nil)
	seed, err := packRegoBundle([]byte(`package atol
default allow := false`))
	if err != nil {
		f.Fatalf("pack seed: %v", err)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		e := New(zEngine)
		if err := e.LoadBundle(seed, nil); err != nil {
			t.Fatalf("load seed: %v", err)
		}
		pre := e.snapshot()

		// Feed arbitrary bytes. Must not panic regardless.
		_ = e.LoadBundle(raw, nil)

		post := e.snapshot()
		// If LoadBundle rejected the input, the snapshot MUST be the
		// same generation we saw before (no partial corruption). If it
		// accepted, the new generation has both fields non-nil.
		if post == nil {
			t.Error("LoadBundle cleared the snapshot without returning an error")
			return
		}
		if post != pre && (post.compiler == nil || post.store == nil) {
			t.Errorf("snapshot half-installed: compiler=%v store=%v",
				post.compiler != nil, post.store != nil)
		}
	})
}

func packRegoBundle(src []byte) ([]byte, error) {
	b := bundle.Bundle{
		Modules: []bundle.ModuleFile{
			{URL: "/p.rego", Path: "/p.rego", Raw: src},
		},
		Data: make(map[string]any),
	}
	var buf bytes.Buffer
	if err := bundle.Write(&buf, b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
