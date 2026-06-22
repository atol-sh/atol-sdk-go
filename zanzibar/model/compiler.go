package model

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// yamlModel is the raw YAML structure for deserialization.
type yamlModel struct {
	Version string                        `yaml:"version"`
	Types   map[string]yamlTypeDefinition `yaml:"types"`
}

type yamlTypeDefinition struct {
	Relations map[string]yamlRelationDef `yaml:"relations"`
}

type yamlRelationDef struct {
	// Direct type assignments: types: [user, identity, team#effective_member]
	Types []string `yaml:"types,omitempty"`
	// Union of other relations or from/lookup rules.
	Union []yamlUnionEntry `yaml:"union,omitempty"`
	// Required marks the relation as requiring at least one direct holder on
	// any object that has one. Compiles to RelationDef.MinHolders = 1. Only
	// valid on pure-direct relations.
	Required bool `yaml:"required,omitempty"`
}

// yamlUnionEntry can be either a string (relation name) or a from/lookup map.
type yamlUnionEntry struct {
	Relation string // plain string entry
	From     string // from/lookup entry
	Lookup   string
}

func (e *yamlUnionEntry) UnmarshalYAML(value *yaml.Node) error {
	// Try as string first.
	if value.Kind == yaml.ScalarNode {
		e.Relation = value.Value
		return nil
	}
	// Try as map with from/lookup.
	if value.Kind == yaml.MappingNode {
		var m map[string]string
		if err := value.Decode(&m); err != nil {
			return err
		}
		e.From = m["from"]
		e.Lookup = m["lookup"]
		if e.From == "" || e.Lookup == "" {
			return fmt.Errorf("from/lookup entry requires both 'from' and 'lookup' fields")
		}
		return nil
	}
	return fmt.Errorf("union entry must be a string or {from, lookup} map")
}

// Compile parses YAML bytes into a validated Model.
func Compile(data []byte) (*Model, error) {
	var raw yamlModel
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if raw.Version == "" {
		raw.Version = "1.0"
	}

	m := &Model{
		Version: raw.Version,
		Types:   make(map[string]*TypeDef, len(raw.Types)),
	}

	// First pass: create type definitions with empty relations.
	for name := range raw.Types {
		m.Types[name] = &TypeDef{
			Name:      name,
			Relations: make(map[string]*RelationDef),
		}
	}

	// Second pass: compile relations.
	for typeName, typeDef := range raw.Types {
		for relName, relDef := range typeDef.Relations {
			compiled, err := compileRelation(m, typeName, relName, relDef)
			if err != nil {
				return nil, fmt.Errorf("type %q relation %q: %w", typeName, relName, err)
			}
			m.Types[typeName].Relations[relName] = compiled
		}
	}

	// Third pass: validate all references.
	if err := validate(m); err != nil {
		return nil, err
	}

	return m, nil
}

func compileRelation(_ *Model, typeName, relName string, raw yamlRelationDef) (*RelationDef, error) {
	rel := &RelationDef{
		Name:        "",
		DirectTypes: raw.Types,
	}

	// If types are specified and no union, this is a direct relation.
	if len(raw.Types) > 0 && len(raw.Union) == 0 {
		rel.Rewrites = []RewriteRule{{Direct: true}}
	} else if len(raw.Union) > 0 {
		// If union is specified, compile each entry. A union relation always
		// includes its own direct tuples (Zanzibar 'this' semantics) in
		// addition to each union member: a tuple written directly on the
		// unioned relation grants it, and so does any member relation.
		rel.Rewrites = append(rel.Rewrites, RewriteRule{Direct: true})
		for _, entry := range raw.Union {
			if entry.From != "" {
				// from/lookup (tuple_to_userset)
				rel.Rewrites = append(rel.Rewrites, RewriteRule{
					FromLookup: &FromLookup{
						From:   entry.From,
						Lookup: entry.Lookup,
					},
				})
			} else if entry.Relation != "" {
				// computed_userset — reference another relation on same type
				rel.Rewrites = append(rel.Rewrites, RewriteRule{
					ComputedRelation: entry.Relation,
				})
			}
		}
	}
	// Neither types nor union leaves Rewrites empty — an empty relation that
	// is valid but does nothing.

	if raw.Required {
		// A floor is only meaningful and atomically countable over a
		// pure-direct relation people write tuples to. Every union relation
		// carries a leading {Direct:true} rewrite plus its members, so a
		// pure-direct relation is precisely one with a single direct rewrite.
		if len(rel.Rewrites) != 1 || !rel.Rewrites[0].Direct {
			return nil, fmt.Errorf("type %q relation %q: 'required' is only valid on a pure-direct relation",
				typeName, relName)
		}
		rel.MinHolders = 1
	}

	return rel, nil
}

func validate(m *Model) error {
	for typeName, typeDef := range m.Types {
		for relName, relDef := range typeDef.Relations {
			// Validate direct types.
			for _, t := range relDef.DirectTypes {
				if err := validateTypeRef(m, typeName, relName, t); err != nil {
					return err
				}
			}

			// Validate rewrites.
			for _, rw := range relDef.Rewrites {
				if rw.ComputedRelation != "" {
					if _, ok := typeDef.Relations[rw.ComputedRelation]; !ok {
						return fmt.Errorf("type %q relation %q: computed relation %q does not exist on type %q",
							typeName, relName, rw.ComputedRelation, typeName)
					}
				}
				if rw.FromLookup != nil {
					// The 'from' relation must exist on this type.
					fromRel, ok := typeDef.Relations[rw.FromLookup.From]
					if !ok {
						return fmt.Errorf("type %q relation %q: from relation %q does not exist on type %q",
							typeName, relName, rw.FromLookup.From, typeName)
					}
					// The 'lookup' relation must exist on at least one target type
					// of the 'from' relation. Types that don't have the lookup
					// relation are skipped during check traversal.
					foundLookup := false
					for _, targetType := range fromRel.DirectTypes {
						baseType, _, _ := strings.Cut(targetType, "#")
						targetTypeDef, ok := m.Types[baseType]
						if !ok {
							continue
						}
						if _, ok := targetTypeDef.Relations[rw.FromLookup.Lookup]; ok {
							foundLookup = true
							break
						}
					}
					if !foundLookup && len(fromRel.DirectTypes) > 0 {
						return fmt.Errorf("type %q relation %q: lookup relation %q does not exist on any target type of from relation %q",
							typeName, relName, rw.FromLookup.Lookup, rw.FromLookup.From)
					}
				}
			}
		}
	}
	return nil
}

func validateTypeRef(m *Model, typeName, relName, typeRef string) error {
	baseType, relRef, hasRel := strings.Cut(typeRef, "#")

	targetType, ok := m.Types[baseType]
	if !ok {
		return fmt.Errorf("type %q relation %q: referenced type %q does not exist", typeName, relName, baseType)
	}

	if hasRel {
		if _, ok := targetType.Relations[relRef]; !ok {
			return fmt.Errorf("type %q relation %q: referenced relation %q does not exist on type %q",
				typeName, relName, relRef, baseType)
		}
	}

	return nil
}
