package utils

import (
    "time"
    "fmt"
)

func GetTimeDistString(diff time.Duration) string {
    var distString string

    daysAgo := int(diff.Hours() / 24)
    if daysAgo == 0 {
        hoursAgo := int(diff.Hours())
        if hoursAgo == 0 {
            minutesAgo := int(diff.Minutes())
            if minutesAgo == 0 {
                distString = fmt.Sprintf("(%d seconds ago)", int(diff.Seconds()))
            } else if minutesAgo == 1 {
                distString = "(1 minute ago)"
            } else {
                distString = fmt.Sprintf("(%d minutes ago)", minutesAgo)
            }
        } else {
            distString = fmt.Sprintf("(%d days ago)", hoursAgo)
        }
    } else if daysAgo == 1 {
        distString = "(yesterday)"
    } else {
        distString = fmt.Sprintf("(%d days ago)", daysAgo)
    }

    return distString
}
