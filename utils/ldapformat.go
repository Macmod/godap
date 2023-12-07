package utils

import (
    "encoding/hex"
    "time"
    "fmt"
    "strconv"
    "github.com/go-ldap/ldap/v3"
)

func FormatLDAPAttribute(attr *ldap.EntryAttribute) []string {
    var formattedEntries = attr.Values

    if len(attr.Values) == 0 {
        return []string{"(Empty)"}
    }

    for idx, val := range attr.Values {
        switch attr.Name {
        case "objectGUID", "objectSid":
            formattedEntries = []string{"HEX{" + hex.EncodeToString(attr.ByteValues[idx]) + "}"}
        case "whenCreated", "whenChanged":
            layout := "20060102150405.0Z"
            t, err := time.Parse(layout, val)
            if err != nil {
                return []string{"Invalid date format"}
            }

            distString := GetTimeDistString(time.Since(t))

            formattedEntries = []string{
                fmt.Sprintf(
                    "%02d/%02d/%d %02d:%02d:%02d %s", t.Day(), t.Month(), t.Year(),
                    t.Hour(), t.Minute(), t.Second(), distString,
                ),
            }
        case "lastLogonTimestamp", "accountExpires", "badPasswordTime", "lastLogoff", "lastLogon", "pwdLastSet", "creationTime", "lockoutTime":
            if val == "0" {
                return []string{"(Never)"}
            }

            if attr.Name == "accountExpires" && val == "9223372036854775807" {
                return []string{"(Never Expire)"}
            }

            intValue, err := strconv.ParseInt(val, 10, 64)
            if err != nil {
                return []string{"(Invalid)"}
            }

            unixTime := (intValue - 116444736000000000) / 10000000
            t := time.Unix(unixTime, 0).UTC()

            distString := GetTimeDistString(time.Since(t))

            formattedEntries = []string{fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d %s", t.Day(), t.Month(), t.Year(), t.Hour(), t.Minute(), t.Second(), distString)}
        case "userAccountControl":
            uacInt, _ := strconv.Atoi(val)

            formattedEntries = []string{}

            if uacInt & UAC_ACCOUNTDISABLE != 0 {
                formattedEntries = append(formattedEntries, "Disabled")
            } else {
                formattedEntries = append(formattedEntries, "Enabled")
            }

            if uacInt & UAC_NORMAL_ACCOUNT != 0 {
                formattedEntries = append(formattedEntries, "Normal")
            } else {
                formattedEntries = append(formattedEntries, "NotNormal")
            }

            if uacInt & UAC_PASSWORD_EXPIRED != 0 {
                formattedEntries = append(formattedEntries, "PwdExpired")
            } else {
                formattedEntries = append(formattedEntries, "PwdNotExpired")
            }
        case "primaryGroupID":
            rId, _ := strconv.Atoi(val)

            groupName, ok := RidMap[rId]

            if ok {
                formattedEntries = []string{groupName}
            }
        case "sAMAccountType":
            sAMAccountTypeId, _ := strconv.Atoi(val)

            accountType, ok := SAMAccountTypeMap[sAMAccountTypeId]

            if ok {
                formattedEntries = []string{accountType}
            }
        case "groupType":
            groupTypeId, _ := strconv.Atoi(val)
            groupType, ok := GroupTypeMap[groupTypeId]

            if ok {
                formattedEntries = []string{groupType}
            }
        case "instanceType":
            instanceTypeId, _ := strconv.Atoi(val)
            instanceType, ok := InstanceTypeMap[instanceTypeId]

            if ok {
                formattedEntries = []string{instanceType}
            }
        default:
            formattedEntries = attr.Values
        }
    }

    return formattedEntries
}
