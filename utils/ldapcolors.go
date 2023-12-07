package utils

import (
    "strconv"
    "time"
)

func GetAttrCellColor(cellName string, cellValue string) (string, bool) {
    var color string = ""

    switch cellName {
    case "lastLogonTimestamp", "accountExpires", "badPasswordTime", "lastLogoff", "lastLogon", "pwdLastSet", "creationTime", "lockoutTime":
        intValue, err := strconv.ParseInt(cellValue, 10, 64)
        if err == nil {
            unixTime := (intValue - 116444736000000000) / 10000000
            t := time.Unix(unixTime, 0).UTC()

            daysDiff := int(time.Since(t).Hours()/24)

            if daysDiff <= 7 {
                color = "green"
            } else if daysDiff <= 90 {
                color = "yellow"
            } else {
                color = "red"
            }
        }
    case "objectGUID", "objectSid":
        color = "gray"
    case "whenCreated", "whenChanged":
        layout := "20060102150405.0Z"
        t, err := time.Parse(layout, cellValue)
        if err == nil {
            daysDiff := int(time.Since(t).Hours()/24)

            if daysDiff <= 7 {
                color = "green"
            } else if daysDiff <= 90 {
                color = "yellow"
            } else {
                color = "red"
            }
        }
    }

    switch cellValue {
    case "TRUE", "Enabled", "Normal", "PwdNotExpired":
        color = "green"
    case "FALSE", "Disabled", "NotNormal", "PwdExpired":
        color = "red"
    }

    if color != "" {
        return color, true
    }

    return "", false
}
