package utils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"
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
