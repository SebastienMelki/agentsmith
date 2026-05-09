// Package ui contains the templ-generated HTML components and view helpers
// for agentsmith's admin dashboard.
package ui

import (
	"fmt"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/gateway"
)

// connectedCount returns the number of backends in StateConnected.
func connectedCount(backends []gateway.BackendStatus) int {
	n := 0
	for _, b := range backends {
		if b.State == gateway.StateConnected {
			n++
		}
	}
	return n
}

// relativeTime formats an optional timestamp as a human-friendly relative
// string ("just now", "3 minutes ago", etc.). Used as the visible text.
func relativeTime(t *time.Time) string {
	if t == nil {
		return "—"
	}
	d := time.Since(*t)
	switch {
	case d < 30*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < 2*time.Minute:
		return "1 minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 2*time.Hour:
		return "1 hour ago"
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	default:
		return t.UTC().Format("Jan 2, 15:04 UTC")
	}
}

// absoluteTime formats an optional timestamp as a full UTC string for use as
// a tooltip title attribute. Returns an empty string for nil.
func absoluteTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
