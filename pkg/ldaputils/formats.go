package ldaputils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Macmod/godap/v2/pkg/formats"
	"github.com/go-ldap/ldap/v3"
)

func HexToOffset(hex string) (integer int64) {
	integer, _ = strconv.ParseInt(EndianConvert(hex), 16, 64)
	integer = integer * 2
	return
}

func EndianConvert(sd string) (newSD string) {
	sdBytes, _ := hex.DecodeString(sd)

	for i, j := 0, len(sdBytes)-1; i < j; i, j = i+1, j-1 {
		sdBytes[i], sdBytes[j] = sdBytes[j], sdBytes[i]
	}

	newSD = hex.EncodeToString(sdBytes)

	return
}

func HexToDecimalString(hex string) (decimal string) {
	integer, _ := strconv.ParseInt(hex, 16, 64)
	decimal = strconv.Itoa(int(integer))

	return
}

func HexToInt(hex string) (integer int) {
	integer64, _ := strconv.ParseInt(hex, 16, 64)
	integer = int(integer64)
	return
}

func Capitalize(str string) string {
	runes := []rune(str)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

func ConvertSID(hexSID string) (SID string) {
	var fields []string
	fields = append(fields, hexSID[0:2])
	if fields[0] == "01" {
		fields[0] = "S-1"
	}
	numDashes, _ := strconv.Atoi(HexToDecimalString(hexSID[2:4]))

	fields = append(fields, "-"+HexToDecimalString(hexSID[4:16]))

	lower, upper := 16, 24
	for i := 1; i <= numDashes; i++ {
		fields = append(fields, "-"+HexToDecimalString(EndianConvert(hexSID[lower:upper])))
		lower += 8
		upper += 8
	}

	for i := 0; i < len(fields); i++ {
		SID += (fields[i])
	}

	return
}

// TODO: Review correctness of this function
func EncodeSID(sid string) (string, error) {
	if len(sid) < 2 {
		return "", fmt.Errorf("Invalid SID format")
	}

	parts := strings.Split(sid[2:], "-")
	if len(parts) < 3 {
		return "", fmt.Errorf("Invalid SID format")
	}

	hexSID := ""

	revision, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("Error parsing revision: %v", err)
	}

	hexSID += fmt.Sprintf("%02X", revision)

	subAuthoritiesCount := len(parts) - 2
	hexSID += fmt.Sprintf("%02X", subAuthoritiesCount)

	identifierAuthority, _ := strconv.Atoi(parts[1])
	for i := 0; i < 6; i++ {
		hexSID += fmt.Sprintf("%02X", byte(identifierAuthority>>(8*(5-i))&0xFF))
	}

	for _, subAuthority := range parts[2:] {
		subAuthorityValue, err := strconv.Atoi(subAuthority)
		if err != nil {
			return "", fmt.Errorf("Error parsing subauthority: %v", err)
		}

		subAuthorityArr := make([]byte, 4)
		binary.LittleEndian.PutUint32(subAuthorityArr, uint32(subAuthorityValue))

		hexSID += fmt.Sprintf("%08X", subAuthorityArr)
	}

	return hexSID, nil
}

func IsSID(s string) bool {
	return strings.HasPrefix(s, "S-")
}

func ConvertGUID(portion string) string {
	portion1 := EndianConvert(portion[0:8])
	portion2 := EndianConvert(portion[8:12])
	portion3 := EndianConvert(portion[12:16])
	portion4 := portion[16:20]
	portion5 := portion[20:]
	return fmt.Sprintf("%s-%s-%s-%s-%s", portion1, portion2, portion3, portion4, portion5)
}

func EncodeGUID(guid string) (string, error) {
	tokens := strings.Split(guid, "-")
	if len(tokens) != 5 {
		return "", fmt.Errorf("Wrong GUID format")
	}

	result := ""
	result += EndianConvert(tokens[0])
	result += EndianConvert(tokens[1])
	result += EndianConvert(tokens[2])
	result += tokens[3]
	result += tokens[4]
	return result, nil
}

func FormatLDAPTime(val, format string) string {
	layout := "20060102150405.0Z"
	t, err := time.Parse(layout, val)
	if err != nil {
		return "Invalid date format"
	}

	distString := formats.GetTimeDistString(time.Since(t))

	return fmt.Sprintf("%s %s", t.Format(format), distString)
}

func FormatLDAPAttribute(attr *ldap.EntryAttribute, timeFormat string) []string {
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
			formattedEntries = []string{
				FormatLDAPTime(val, timeFormat),
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

			distString := formats.GetTimeDistString(time.Since(t))

			formattedEntries = []string{fmt.Sprintf("%s %s", t.Format(timeFormat), distString)}
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
