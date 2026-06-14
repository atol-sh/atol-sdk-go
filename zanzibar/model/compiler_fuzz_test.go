package model

import (
	"testing"
)

// FuzzCompile feeds arbitrary YAML bytes into the Zanzibar model compiler.
// A malformed model bundle must always return an error -- never panic or
// produce a nil Model pointer that the caller tries to deref.
func FuzzCompile(f *testing.F) {
	// Minimal valid model as a seed.
	f.Add([]byte(`
types:
  - name: doc
    relations:
      owner: { self: true }
`))
	f.Add([]byte(``))
	f.Add([]byte(`not: yaml: at: all: :::`))
	f.Add([]byte(`types: []`))
	f.Add([]byte(`types:
  - name: ""
    relations:
      "": { self: true }`))
	f.Add([]byte("\x00\x00\x00"))
	// Anchors / aliases / merge keys: common YAML parser crash surface.
	f.Add([]byte(`
types:
  - &a
    name: doc
    relations:
      owner: { self: true }
  - <<: *a
`))
	// Very large input to exercise memory handling.
	f.Add(make([]byte, 1<<14))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Compile(data)
		if err == nil && m == nil {
			t.Fatal("Compile returned nil model with nil error")
		}
		// Failure modes: Compile returning a non-nil model AND a non-nil
		// error is a bug; callers shouldn't have to guess.
		if err != nil && m != nil {
			t.Errorf("Compile returned both model and error: model=%v err=%v", m, err)
		}
	})
}
