//go:build !linux && !darwin

package tui

// defaultCCachePath is a no-op outside Linux/macOS: the /tmp/krb5cc_<uid>
// convention doesn't apply on Windows (no /tmp, no POSIX UID).
func defaultCCachePath() string {
	return ""
}
