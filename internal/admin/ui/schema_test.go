package ui

import (
	"strings"
	"testing"
)

// TestParseSchema_DepthCapTruncates pins the recursion guard: a schema
// nested deeper than maxSchemaDepth must produce a truncated leaf rather
// than blowing the stack. The test builds an object-of-object chain
// (depth maxSchemaDepth+5) and walks the resulting tree to find the
// truncation marker.
func TestParseSchema_DepthCapTruncates(t *testing.T) {
	const overrun = 5
	depth := maxSchemaDepth + overrun

	// Build the JSON inside-out: innermost schema first, then wrap it in
	// `{"type":"object","properties":{"k":<inner>}}` `depth` times.
	inner := `{"type":"string"}`
	for range depth {
		inner = `{"type":"object","properties":{"k":` + inner + `}}`
	}

	root, err := ParseSchema(inner)
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	// Walk the chain through repeated `k` children. We should reach a node
	// whose Type is "..." (the truncation marker) within depth+1 hops.
	cur := root
	for i := range depth + overrun {
		if cur == nil {
			t.Fatalf("ran out of nodes at depth %d (input nested %d levels deep)", i, depth)
		}
		if cur.Type == "..." {
			if !strings.Contains(cur.Description, "truncated") {
				t.Errorf("truncation marker missing description; got %+v", cur)
			}
			return
		}
		// Descend into the single "k" child.
		next := childByName(cur, "k")
		if next == nil {
			// Reached a leaf without finding the marker — fine only if we
			// actually consumed the whole chain (not the case here, since
			// depth > maxSchemaDepth).
			t.Fatalf("hit leaf at hop %d without truncation; tree shorter than expected", i)
		}
		cur = next
	}
	t.Fatal("walked the whole chain without finding the truncation marker")
}

// TestParseSchema_NormalSchemasUntouched confirms the depth cap does not
// regress shallow schemas.
func TestParseSchema_NormalSchemasUntouched(t *testing.T) {
	const in = `{
		"type": "object",
		"properties": {
			"name":  {"type": "string"},
			"items": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "integer"}}}}
		},
		"required": ["name"]
	}`
	root, err := ParseSchema(in)
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	if root == nil || root.Type != "object" {
		t.Fatalf("unexpected root: %+v", root)
	}
	if name := childByName(root, "name"); name == nil || name.Type != "string" || !name.Required {
		t.Errorf("name child wrong: %+v", name)
	}
	items := childByName(root, "items")
	if items == nil || items.Type != "array" {
		t.Fatalf("items child wrong: %+v", items)
	}
	itemsChild := childByName(items, "items")
	if itemsChild == nil || itemsChild.Type != "object" {
		t.Errorf("items.items wrong: %+v", itemsChild)
	}
	id := childByName(itemsChild, "id")
	if id == nil || id.Type != "integer" {
		t.Errorf("items.items.id wrong: %+v", id)
	}
}

func childByName(n *SchemaNode, name string) *SchemaNode {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}
