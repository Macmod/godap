package utils

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func FormatLDAPAttribute(attr *ldap.EntryAttribute) []string {
	var formattedEntries = attr.Values

	if len(attr.Values) == 0 {
		return []string{"(Empty)"}
	}

	for idx, val := range attr.Values {
		switch attr.Name {
		case "objectSid":
			formattedEntries = []string{"SID{" + ConvertSID(hex.EncodeToString(attr.ByteValues[idx])) + "}"}
		case "objectGUID", "schemaIDGUID":
			formattedEntries = []string{"GUID{" + ConvertGUID(hex.EncodeToString(attr.ByteValues[idx])) + "}"}
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

			uacFlagKeys := make([]int, 0)
			for k, _ := range UacFlags {
				uacFlagKeys = append(uacFlagKeys, k)
			}
			sort.Ints(uacFlagKeys)

			for _, flag := range uacFlagKeys {
				curFlag := UacFlags[flag]
				if uacInt&flag != 0 {
					if curFlag.Present != "" {
						formattedEntries = append(formattedEntries, curFlag.Present)
					}
				} else {
					if curFlag.NotPresent != "" {
						formattedEntries = append(formattedEntries, curFlag.NotPresent)
					}
				}
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
