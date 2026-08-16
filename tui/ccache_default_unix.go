//go:build linux || darwin

package tui

import (
	"fmt"
	"os"
)

// defaultCCachePath returns the conventional ccache location MIT Kerberos
// tooling (kinit/klist) falls back to when KRB5CCNAME isn't set.
func defaultCCachePath() string {
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
}
