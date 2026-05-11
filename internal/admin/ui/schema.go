package ui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SchemaNode is a normalized JSON-Schema node used by the recursive
// schemaRow / SchemaTree templ components on the backend detail page.
//
// The Children slice holds property nodes for objects (sorted
// alphabetically by Name) and a single node named "items" for arrays.
type SchemaNode struct {
	Name                   string
	Type                   string
	Nullable               bool // declared as `["null", T]` in a type union
	Description            string
	Required               bool
	Default                string
	Enum                   []string
	Format                 string
	Pattern                string
	Minimum                *float64
	Maximum                *float64
	MinLength              *int
	MaxLength              *int
	AdditionalPropsAllowed bool
	Children               []*SchemaNode
}

// ParseSchema decodes a pretty-printed JSON-Schema string into a
// SchemaNode tree. An empty input returns (nil, nil) — callers treat
// missing schemas as "no tree to render". Malformed JSON returns an
// error so the section can fall back to a Raw-only view.
func ParseSchema(rawJSON string) (*SchemaNode, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return nil, nil
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	return parseNode("", raw, false), nil
}

func parseNode(name string, raw map[string]any, required bool) *SchemaNode {
	n := &SchemaNode{
		Name:                   name,
		Required:               required,
		AdditionalPropsAllowed: true,
	}
	if raw == nil {
		return n
	}

	n.Type, n.Nullable = readType(raw["type"])
	n.Description, _ = raw["description"].(string)
	n.Format, _ = raw["format"].(string)
	n.Pattern, _ = raw["pattern"].(string)

	if v, ok := raw["default"]; ok {
		if b, err := json.Marshal(v); err == nil {
			n.Default = string(b)
		}
	}
	if enum, ok := raw["enum"].([]any); ok {
		for _, e := range enum {
			if b, err := json.Marshal(e); err == nil {
				n.Enum = append(n.Enum, string(b))
			}
		}
	}
	if f, ok := numAsFloat(raw["minimum"]); ok {
		n.Minimum = &f
	}
	if f, ok := numAsFloat(raw["maximum"]); ok {
		n.Maximum = &f
	}
	if i, ok := numAsInt(raw["minLength"]); ok {
		n.MinLength = &i
	}
	if i, ok := numAsInt(raw["maxLength"]); ok {
		n.MaxLength = &i
	}
	if ap, ok := raw["additionalProperties"]; ok {
		if b, isBool := ap.(bool); isBool && !b {
			n.AdditionalPropsAllowed = false
		}
	}

	// Object: walk properties, alpha-sort, inherit required.
	if props, ok := raw["properties"].(map[string]any); ok {
		requiredSet := map[string]bool{}
		if rs, ok := raw["required"].([]any); ok {
			for _, r := range rs {
				if s, ok := r.(string); ok {
					requiredSet[s] = true
				}
			}
		}
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child, ok := props[k].(map[string]any)
			if !ok {
				continue
			}
			n.Children = append(n.Children, parseNode(k, child, requiredSet[k]))
		}
	}

	// Array: one child named "items" representing the item schema.
	if items, ok := raw["items"].(map[string]any); ok {
		n.Children = append(n.Children, parseNode("items", items, false))
	}

	return n
}

// readType extracts the type label for a schema node. It also detects
// the `["null", T]` nullable-T idiom (common because draft-7 JSON Schema
// has no `nullable` keyword) and returns the non-null type with a
// nullable flag, so the renderer can show "array<object>" + "nullable"
// instead of an opaque "null | array" union.
func readType(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, false
	case []any:
		parts := make([]string, 0, len(t))
		nullable := false
		for _, p := range t {
			s, ok := p.(string)
			if !ok {
				continue
			}
			if s == "null" {
				nullable = true
				continue
			}
			parts = append(parts, s)
		}
		if len(parts) == 1 {
			return parts[0], nullable
		}
		return strings.Join(parts, " | "), nullable
	}
	return "", false
}

func numAsFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

func numAsInt(v any) (int, bool) {
	if f, ok := numAsFloat(v); ok {
		return int(f), true
	}
	return 0, false
}

// indentStyle returns the inline style used to indent a schema row by
// `depth * 18px`. Used as a templ attribute expression.
func indentStyle(depth int) string {
	return fmt.Sprintf("padding-left: %dpx", depth*18)
}

// typePillClass maps a SchemaNode.Type to the CSS class for its type pill.
// Unknown / type-union strings fall back to "type-any".
func typePillClass(t string) string {
	switch t {
	case "string":
		return "type-string"
	case "number":
		return "type-number"
	case "integer":
		return "type-integer"
	case "boolean":
		return "type-boolean"
	case "object":
		return "type-object"
	case "array":
		return "type-array"
	case "null":
		return "type-null"
	}
	return "type-any"
}

// typePillText returns the human-readable type label for a node. Arrays
// compose to `array<itemType>` so the items row in an array-of-object
// schema reads "array<object>" without needing an intermediate row.
func typePillText(n *SchemaNode) string {
	if n == nil {
		return "any"
	}
	if n.Type == "" {
		return "any"
	}
	if n.Type == "array" {
		itemType := arrayItemType(n)
		if itemType != "" {
			return "array<" + itemType + ">"
		}
		return "array"
	}
	return n.Type
}

func arrayItemType(n *SchemaNode) string {
	for _, c := range n.Children {
		if c.Name == "items" {
			if c.Type == "" {
				return "any"
			}
			if c.Type == "array" {
				return "array<" + arrayItemType(c) + ">"
			}
			return c.Type
		}
	}
	return ""
}

// arrayItemsChild returns the single "items" child node of an array
// schema node, or nil if the array has no item schema.
func arrayItemsChild(n *SchemaNode) *SchemaNode {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Name == "items" {
			return c
		}
	}
	return nil
}
