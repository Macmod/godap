package sdl

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

//https://www.itinsights.org/Process-low-level-NtSecurityDescriptor/

func getHeader(SD string) *HEADER {
	header := new(HEADER)
	header.Revision = SD[0:2]
	header.Sbz1 = endianConvert(SD[2:4])
	header.Control = endianConvert(SD[4:8])
	header.OffsetOwner = endianConvert(SD[8:16])
	header.OffsetGroup = endianConvert(SD[16:24])
	header.OffsetSacl = endianConvert(SD[24:32])
	header.OffsetDacl = endianConvert(SD[32:40])

	return header
}

func getACLHeader(SD string) *ACLHEADER {
	ACLHeader := new(ACLHEADER)
	ACLHeader.ACLRevision = SD[40:42]
	ACLHeader.Sbz1 = endianConvert(SD[42:44])
	ACLHeader.ACLSizeBytes = endianConvert(SD[44:48])
	ACLHeader.ACECount = endianConvert(SD[48:52])
	ACLHeader.Sbz2 = endianConvert(SD[52:56])

	return ACLHeader
}

func getACEHeader(SD string) *ACEHEADER {
	ACEHeader := new(ACEHEADER)
	ACEHeader.ACEType = SD[0:2]
	ACEHeader.ACEFlags = SD[2:4]
	ACEHeader.AceSizeBytes = endianConvert(SD[4:8])

	return ACEHeader
}

func getACEMask(ACE string) (ACEMask string) {
	ACEMask = endianConvert(ACE[8:16])

	return ACEMask
}

func getACEFlags(ACE string) (ACEFlags string) {
	ACEFlags = endianConvert(ACE[16:24])

	return ACEFlags
}

func getOwner(header *HEADER, sd string) (ownerSID string) {
	offset := hexToOffset(header.OffsetOwner)
	ownerHexSID := sd[offset : offset+56]
	ownerSID = convertSID(ownerHexSID)

	return
}

func GetGroup(header *HEADER, sd string) (groupSID string) {
	offset := hexToOffset(header.OffsetGroup)
	groupHexSID := sd[offset : offset+56]
	groupSID = convertSID(groupHexSID)

	return
}

func getObjectAndInheritedType(ACE string, ACEFlags string) (objectTypeGUID string, inheritedObjectTypeGUID string) {
	//ObjectType field existent
	if ACEFlags == "00000001" {
		objectType := ACE[24:56]
		portion1 := endianConvert(objectType[0:8])
		portion2 := endianConvert(objectType[8:12])
		portion3 := endianConvert(objectType[12:16])
		portion4 := objectType[16:20]
		portion5 := objectType[20:]
		objectTypeGUID = fmt.Sprintf("%s-%s-%s-%s-%s", portion1, portion2, portion3, portion4, portion5)
		inheritedObjectTypeGUID = ""
		//InheritedObjectType field existent
	} else if ACEFlags == "00000002" {
		inheritedObjectType := ACE[24:56]
		portion1 := endianConvert(inheritedObjectType[0:8])
		portion2 := endianConvert(inheritedObjectType[8:12])
		portion3 := endianConvert(inheritedObjectType[12:16])
		portion4 := inheritedObjectType[16:20]
		portion5 := inheritedObjectType[20:]
		inheritedObjectTypeGUID = fmt.Sprintf("%s-%s-%s-%s-%s", portion1, portion2, portion3, portion4, portion5)
		objectTypeGUID = ""
		//Both fields existent
	} else if ACEFlags == "00000003" {
		objectType := ACE[24:56]
		portion1 := endianConvert(objectType[0:8])
		portion2 := endianConvert(objectType[8:12])
		portion3 := endianConvert(objectType[12:16])
		portion4 := objectType[16:20]
		portion5 := objectType[20:]
		objectTypeGUID = fmt.Sprintf("%s-%s-%s-%s-%s", portion1, portion2, portion3, portion4, portion5)

		inheritedObjectType := ACE[56:88]
		portion1 = endianConvert(inheritedObjectType[0:8])
		portion2 = endianConvert(inheritedObjectType[8:12])
		portion3 = endianConvert(inheritedObjectType[12:16])
		portion4 = inheritedObjectType[16:20]
		portion5 = inheritedObjectType[20:]
		inheritedObjectTypeGUID = fmt.Sprintf("%s-%s-%s-%s-%s", portion1, portion2, portion3, portion4, portion5)
	}

	return
}

func endianConvert(sd string) (newSD string) {
	sdBytes, _ := hex.DecodeString(sd)

	for i, j := 0, len(sdBytes)-1; i < j; i, j = i+1, j-1 {
		sdBytes[i], sdBytes[j] = sdBytes[j], sdBytes[i]
	}

	newSD = hex.EncodeToString(sdBytes)

	return
}

func hexToOffset(hex string) (integer int64) {
	integer, _ = strconv.ParseInt(hex, 16, 64)
	integer = integer * 2
	return
}

func hexToDecimalString(hex string) (decimal string) {
	integer, _ := strconv.ParseInt(hex, 16, 64)
	decimal = strconv.Itoa(int(integer))

	return
}

func convertSID(hexSID string) (SID string) {
	//https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253
	var fields []string
	fields = append(fields, hexSID[0:2])
	if fields[0] == "01" {
		fields[0] = "S-1"
	}
	numDashes, _ := strconv.Atoi(hexToDecimalString(hexSID[2:4]))

	fields = append(fields, "-"+hexToDecimalString(hexSID[4:16]))

	lower, upper := 16, 24
	for i := 1; i <= numDashes; i++ {
		fields = append(fields, "-"+hexToDecimalString(endianConvert(hexSID[lower:upper])))
		lower += 8
		upper += 8
	}

	for i := 0; i < len(fields); i++ {
		SID += (fields[i])
	}

	return
}

func getDACL(header *HEADER, sd string) (DACL string) {
	offset := hexToOffset(header.OffsetDacl)
	DACL = sd[offset:]

	return
}

func getACE(rawACE string) (ACE string) {
	aceLengthBytes, _ := strconv.Atoi(hexToDecimalString(endianConvert(rawACE[4:8])))
	aceLength := aceLengthBytes * 2
	ACE = rawACE[:aceLength]

	return
}

func getSID(ACE string) (SID string) {
	SID = ACE[len(ACE)-56:]

	return
}

func hexToInt(hex string) (integer int) {
	integer64, _ := strconv.ParseInt(hex, 16, 64)
	integer = int(integer64)
	return
}

func ParseSD(conn *ldap.Conn, baseDN string, SD string) (acesList []ACESList) {
	header := getHeader(SD)
	ACLHeader := getACLHeader(SD)
	DACL := getDACL(header, SD)
	rawACES := DACL[16:]
	aceCount, _ := strconv.Atoi(hexToDecimalString(ACLHeader.ACECount))
	rawACESList := make([]string, aceCount)

	for i := 0; i < aceCount; i++ {
		rawACESList[i] = getACE(rawACES)
		rawACES = rawACES[len(rawACESList[i]):]
	}

	abusableAces := []ACESList{}
	for ace, _ := range rawACESList {
		entry := ACESList{SamAccountName: "", GENERIC_ALL: false, GENERIC_WRITE: false, WRITE_OWNER: false, WRITE_DACL: false, FORCE_CHANGE_PASSWORD: false, ADD_MEMBER: false}

		aceHeader := getACEHeader(rawACESList[ace])
		aceType, _ := strconv.Atoi(aceHeader.ACEType)

		var resolvedACEType string
		for entry, _ := range aceTypeMap {
			if entry == aceType {
				resolvedACEType = aceTypeMap[entry]
			}

		}

		switch resolvedACEType {
		case "ACCESS_ALLOWED_ACE_TYPE":
			ACE := new(ACCESS_ALLOWED_ACE)
			ACE.parse(rawACESList[ace], baseDN, conn)
			entry.SamAccountName = ACE.samAccountName

			permissions, err := strconv.ParseInt(ACE.mask, 16, 64)
			if err != nil {
				fmt.Printf("ACE Mask Conversion Error, %s\n", err)
			}

			if permissions&int64(accessRightsMap["RIGHT_DS_CREATE_CHILD"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_DELETE_CHILD"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_LIST_CONTENTS"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_WRITE_PROPERTY_EXTENDED"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_READ_PROPERTY"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_WRITE_PROPERTY"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_DELETE_TREE"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_LIST_OBJECT"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_CONTROL_ACCESS"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DELETE"]) > 0 && permissions&int64(accessRightsMap["RIGHT_READ_CONTROL"]) > 0 && permissions&int64(accessRightsMap["RIGHT_WRITE_DACL"]) > 0 && permissions&int64(accessRightsMap["RIGHT_WRITE_OWNER"]) > 0 {
				entry.GENERIC_ALL = true
			}

			if permissions&int64(accessRightsMap["RIGHT_WRITE_DACL"]) > 0 {
				entry.WRITE_DACL = true
			}

			if permissions&int64(accessRightsMap["RIGHT_WRITE_OWNER"]) > 0 {
				entry.WRITE_OWNER = true
			}

			if permissions&int64(accessRightsMap["RIGHT_READ_CONTROL"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_WRITE_PROPERTY"]) > 0 && permissions&int64(accessRightsMap["RIGHT_DS_WRITE_PROPERTY_EXTENDED"]) > 0 {
				entry.GENERIC_WRITE = true
			}

			inArray := false
			for index := range abusableAces {
				if entry.SamAccountName == abusableAces[index].SamAccountName {
					inArray = true
					abusableAces[index].GENERIC_ALL = entry.GENERIC_ALL
					abusableAces[index].WRITE_DACL = entry.WRITE_DACL
					abusableAces[index].WRITE_OWNER = entry.WRITE_OWNER
					abusableAces[index].GENERIC_WRITE = entry.GENERIC_WRITE
				}
			}

			if !inArray {
				abusableAces = append(abusableAces, entry)
			}

		case "ACCESS_ALLOWED_OBJECT_ACE_TYPE":
			ACE := new(ACCESS_ALLOWED_OBJECT_ACE)
			ACE.parse(rawACESList[ace], baseDN, conn)
			entry.SamAccountName = ACE.samAccountName

			if ACE.objectType == "00299570-246d-11d0-a768-00aa006e0529" {
				entry.FORCE_CHANGE_PASSWORD = true
			}

			if ACE.objectType == "bf9679c0-0de6-11d0-a285-00aa003049e2" {
				entry.ADD_MEMBER = true
			}

			inArray := false
			for index := range abusableAces {
				if entry.SamAccountName == abusableAces[index].SamAccountName {
					inArray = true
					abusableAces[index].FORCE_CHANGE_PASSWORD = entry.FORCE_CHANGE_PASSWORD
					abusableAces[index].ADD_MEMBER = entry.ADD_MEMBER
				}
			}

			if !inArray {
				abusableAces = append(abusableAces, entry)
			}
		}

	}

	return abusableAces
}
