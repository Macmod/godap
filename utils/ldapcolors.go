package utils

import (
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/go-ldap/ldap/v3"
)

func GetEntryColor(entry *ldap.Entry) (tcell.Color, bool) {
	isDeleted := strings.ToLower(entry.GetAttributeValue("isDeleted")) == "true"
	isRecycled := strings.ToLower(entry.GetAttributeValue("isRecycled")) == "true"

	if isDeleted {
		if isRecycled {
			return tcell.GetColor("red"), true
		} else {
			return tcell.GetColor("gray"), true
		}
	} else {
		uac := entry.GetAttributeValue("userAccountControl")
		uacNum, err := strconv.Atoi(uac)

		if err == nil && uacNum&2 != 0 {
			return tcell.GetColor("yellow"), true
		}
	}

	return tcell.ColorDefault, false
}

func GetAttrCellColor(cellName string, cellValue string) (string, bool) {
	var color string = ""

	switch cellName {
	case "lastLogonTimestamp", "accountExpires", "badPasswordTime", "lastLogoff", "lastLogon", "pwdLastSet", "creationTime", "lockoutTime":
		intValue, err := strconv.ParseInt(cellValue, 10, 64)
		if err == nil {
			unixTime := (intValue - 116444736000000000) / 10000000
			t := time.Unix(unixTime, 0).UTC()

			daysDiff := int(time.Since(t).Hours() / 24)

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
			daysDiff := int(time.Since(t).Hours() / 24)

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
	case "FALSE", "NotNormal", "PwdExpired":
		color = "red"
	case "Disabled":
		color = "yellow"
	}

	if color != "" {
		return color, true
	}

	return "", false
}
