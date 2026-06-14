package policy

import (
	"bytes"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/bundle"

	"atol.sh/sdk-go/zanzibar/model"
)

func TestGenerateDefaultPolicy_NilModel(t *testing.T) {
	data, err := GenerateDefaultPolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertValidBundle(t, data)
	rego := extractRegoSource(t, data)
	assertContains(t, rego, `package atol`)
	assertContains(t, rego, `default allow := false`)
	assertContains(t, rego, `zanzibar.check(input.user, input.relation, input.object)`)
}

func TestGenerateDefaultPolicy_DeviceEnforcement(t *testing.T) {
	data, err := GenerateDefaultPolicy(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertValidBundle(t, data)
	rego := extractRegoSource(t, data)

	// Bot and anomaly blocks must be present and wired into the allow rules.
	assertContains(t, rego, `not device_blocked`)
	assertContains(t, rego, `input.device.signals.bot == true`)
	assertContains(t, rego, `input.device.signals.anomaly_score > data.atol.device_max_anomaly_score`)
}

func TestGenerateDefaultPolicy_EmptyModel(t *testing.T) {
	m := &model.Model{
		Version: "1.0",
		Types:   map[string]*model.TypeDef{},
	}

	data, err := GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertValidBundle(t, data)
	rego := extractRegoSource(t, data)
	assertContains(t, rego, `package atol`)
	assertContains(t, rego, `default allow := false`)
	// No model coverage section for empty model.
	assertNotContains(t, rego, `Model coverage`)
}

func TestGenerateDefaultPolicy_WithTypes(t *testing.T) {
	m := &model.Model{
		Version: "1.0",
		Types: map[string]*model.TypeDef{
			"user": {
				Name: "user",
				Relations: map[string]*model.RelationDef{
					"same_identity": {Name: "same_identity", DirectTypes: []string{"identity"}},
				},
			},
			"org": {
				Name: "org",
				Relations: map[string]*model.RelationDef{
					"owner":  {Name: "owner", DirectTypes: []string{"user"}},
					"admin":  {Name: "admin", DirectTypes: []string{"user"}},
					"member": {Name: "member", DirectTypes: []string{"user"}},
				},
			},
			"document": {
				Name: "document",
				Relations: map[string]*model.RelationDef{
					"editor": {Name: "editor", DirectTypes: []string{"user"}},
					"viewer": {Name: "viewer", DirectTypes: []string{"user"}},
				},
			},
		},
	}

	data, err := GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertValidBundle(t, data)
	rego := extractRegoSource(t, data)

	// Core policy.
	assertContains(t, rego, `package atol`)
	assertContains(t, rego, `default allow := false`)
	assertContains(t, rego, `zanzibar.check(input.user, input.relation, input.object)`)

	// Model coverage comments — types sorted alphabetically.
	assertContains(t, rego, `# Object types and relations derived from the Zanzibar model:`)
	assertContains(t, rego, `#   document: editor, viewer`)
	assertContains(t, rego, `#   org: admin, member, owner`)
	assertContains(t, rego, `#   user: same_identity`)
}

func TestGenerateDefaultPolicy_TypeWithNoRelations(t *testing.T) {
	m := &model.Model{
		Version: "1.0",
		Types: map[string]*model.TypeDef{
			"token": {
				Name:      "token",
				Relations: map[string]*model.RelationDef{},
			},
		},
	}

	data, err := GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertValidBundle(t, data)
	rego := extractRegoSource(t, data)
	assertContains(t, rego, `#   token (no relations)`)
}

func TestGenerateDefaultPolicy_DeterministicOutput(t *testing.T) {
	m := &model.Model{
		Version: "1.0",
		Types: map[string]*model.TypeDef{
			"zebra": {Name: "zebra", Relations: map[string]*model.RelationDef{
				"keeper": {Name: "keeper"},
			}},
			"alpha": {Name: "alpha", Relations: map[string]*model.RelationDef{
				"zulu":  {Name: "zulu"},
				"bravo": {Name: "bravo"},
			}},
		},
	}

	// Generate twice and verify identical output.
	data1, err := GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("first generation failed: %v", err)
	}
	data2, err := GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("second generation failed: %v", err)
	}

	rego1 := extractRegoSource(t, data1)
	rego2 := extractRegoSource(t, data2)
	if rego1 != rego2 {
		t.Errorf("non-deterministic output:\n--- first ---\n%s\n--- second ---\n%s", rego1, rego2)
	}

	// Verify alphabetical ordering.
	alphaIdx := strings.Index(rego1, "#   alpha:")
	zebraIdx := strings.Index(rego1, "#   zebra:")
	if alphaIdx < 0 || zebraIdx < 0 {
		t.Fatal("expected both alpha and zebra in coverage comments")
	}
	if alphaIdx >= zebraIdx {
		t.Error("types should be sorted alphabetically: alpha before zebra")
	}
}

func TestGenerateDefaultRegoSource(t *testing.T) {
	m := &model.Model{
		Version: "1.0",
		Types: map[string]*model.TypeDef{
			"user": {Name: "user", Relations: map[string]*model.RelationDef{
				"self": {Name: "self"},
			}},
		},
	}

	source := GenerateDefaultRegoSource(m)
	assertContains(t, source, `package atol`)
	assertContains(t, source, `zanzibar.check(input.user, input.relation, input.object)`)
	assertContains(t, source, `#   user: self`)
}

func TestGenerateDefaultPolicy_BundleRoundTrip(t *testing.T) {
	m := &model.Model{
		Version: "1.0",
		Types: map[string]*model.TypeDef{
			"org": {Name: "org", Relations: map[string]*model.RelationDef{
				"admin": {Name: "admin", DirectTypes: []string{"user"}},
			}},
			"user": {Name: "user", Relations: map[string]*model.RelationDef{}},
		},
	}

	data, err := GenerateDefaultPolicy(m)
	if err != nil {
		t.Fatalf("generation failed: %v", err)
	}

	// Verify the bundle can be read back by OPA.
	reader := bundle.NewReader(bytes.NewReader(data))
	b, err := reader.Read()
	if err != nil {
		t.Fatalf("read bundle back: %v", err)
	}

	if len(b.Modules) != 1 {
		t.Fatalf("module count = %d, want 1", len(b.Modules))
	}

	mod := b.Modules[0]
	if mod.Parsed == nil {
		t.Fatal("parsed module is nil — bundle should contain valid Rego")
	}
	if mod.Parsed.Package.Path.String() != "data.atol" {
		t.Errorf("package path = %q, want %q", mod.Parsed.Package.Path.String(), "data.atol")
	}
}

// --- helpers ---

func assertValidBundle(t *testing.T, data []byte) {
	t.Helper()
	if len(data) == 0 {
		t.Fatal("bundle data is empty")
	}
	reader := bundle.NewReader(bytes.NewReader(data))
	_, err := reader.Read()
	if err != nil {
		t.Fatalf("invalid OPA bundle: %v", err)
	}
}

func extractRegoSource(t *testing.T, data []byte) string {
	t.Helper()
	reader := bundle.NewReader(bytes.NewReader(data))
	b, err := reader.Read()
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if len(b.Modules) == 0 {
		t.Fatal("bundle has no modules")
	}
	return string(b.Modules[0].Raw)
}

func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected output to contain %q, got:\n%s", substr, s)
	}
}

func assertNotContains(t *testing.T, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("expected output NOT to contain %q, got:\n%s", substr, s)
	}
}
