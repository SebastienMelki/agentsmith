// Package ui contains the templ-generated HTML components and view helpers
// for agentsmith's admin dashboard.
package ui

import (
	"fmt"
	"time"

	"github.com/sebastienmelki/agentsmith/internal/gateway"
)

// connectedCount returns the number of backends in StateConnected.
func connectedCount(backends []gateway.BackendDetail) int {
	n := 0
	for i := range backends {
		if backends[i].State == gateway.StateConnected {
			n++
		}
	}
	return n
}

// fmtAvgMs formats an average latency as "Xms", or "—" if no calls yet.
func fmtAvgMs(totalMs, totalCalls int64) string {
	if totalCalls == 0 {
		return "—"
	}
	return fmt.Sprintf("%dms", totalMs/totalCalls)
}

// fmtPct formats a ratio as a percentage string, e.g. "4.2%".
func fmtPct(num, denom int64) string {
	if denom == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(num)/float64(denom)*100)
}

// errorColor returns an inline style for a non-zero error count.
func errorColor(errors int64) string {
	if errors > 0 {
		return "color: #eb5757;"
	}
	return ""
}

// logRowBorder returns the border-left style for a call log row.
func logRowBorder(success bool) string {
	if success {
		return "border-left: 3px solid #1a4731; padding-left: 0.5rem; margin-bottom: 0.4rem;"
	}
	return "border-left: 3px solid #4a1010; padding-left: 0.5rem; margin-bottom: 0.4rem;"
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
