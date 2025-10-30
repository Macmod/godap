package formats

import (
	"fmt"
	"time"
)

func GetTimeDistString(diff time.Duration) string {
	if diff == 0 {
		return "(0 seconds ago)"
	}

	future := diff < 0
	if future {
		diff = -diff
	}

	days := int(diff.Hours() / 24)
	var distString string

	if days == 0 {
		hours := int(diff.Hours())
		if hours == 0 {
			minutes := int(diff.Minutes())
			if minutes == 0 {
				seconds := int(diff.Seconds())
				if future {
					distString = fmt.Sprintf("(%d seconds from now)", seconds)
				} else {
					distString = fmt.Sprintf("(%d seconds ago)", seconds)
				}
			} else if minutes == 1 {
				if future {
					distString = "(1 minute from now)"
				} else {
					distString = "(1 minute ago)"
				}
			} else {
				if future {
					distString = fmt.Sprintf("(%d minutes from now)", minutes)
				} else {
					distString = fmt.Sprintf("(%d minutes ago)", minutes)
				}
			}
		} else if hours == 1 {
			if future {
				distString = "(1 hour from now)"
			} else {
				distString = "(1 hour ago)"
			}
		} else {
			if future {
				distString = fmt.Sprintf("(%d hours from now)", hours)
			} else {
				distString = fmt.Sprintf("(%d hours ago)", hours)
			}
		}
	} else if days == 1 {
		if future {
			distString = "(tomorrow)"
		} else {
			distString = "(yesterday)"
		}
	} else {
		if future {
			distString = fmt.Sprintf("(%d days from now)", days)
		} else {
			distString = fmt.Sprintf("(%d days ago)", days)
		}
	}

	return distString
}
