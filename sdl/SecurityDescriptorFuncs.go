package sdl

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode"

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

func getGroup(header *HEADER, sd string) (groupSID string) {
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

func capitalize(str string) string {
	runes := []rune(str)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

func checkRightExact(mask int, right int) bool {
	return mask&right == right
}

func checkRight(mask int, right int) bool {
	return mask&right != 0
}

func combinePerms(rights []int, rightNames []string, mask int) string {
	var combined []string

	for idx, right := range rights {
		if checkRightExact(mask, right) {
			combined = append(combined, rightNames[idx])
		}
	}

	return capitalize(strings.Join(combined, "/"))
}

// Reference:
// http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
// At the moment this is an experimental & testing accuracy of the parser is hard.
// There are probably some bugs, bug they can be solved in the future :-)
func AceMaskToText(mask int, guid string) ([]string, int) {
	var (
		classNeeded     bool
		attributeNeeded bool
		extendedNeeded  bool
		validatedNeeded bool
		objectclass     string
		attribute       string
		extended        string
		validated       string
		ok              bool
		okClass         bool
		okAttr          bool
	)

	classNeeded = checkRight(mask, accessRightsMap["RIGHT_DS_CREATE_CHILD"]) || checkRight(mask, accessRightsMap["RIGHT_DS_DELETE_CHILD"])
	attributeNeeded = checkRight(mask, accessRightsMap["RIGHT_DS_READ_PROPERTY"]) || checkRight(mask, accessRightsMap["RIGHT_DS_WRITE_PROPERTY"])
	extendedNeeded = checkRight(mask, accessRightsMap["RIGHT_DS_CONTROL_ACCESS"])
	validatedNeeded = checkRight(mask, accessRightsMap["RIGHT_DS_SELF"])

	if len(guid) > 0 {
		ok = true
		if classNeeded && attributeNeeded {
			objectclass, okClass = classesGuidMap[guid]
			attribute, okAttr = attributesGuidMap[guid]

			if !okClass {
				objectclass = "any class of"
			} else if !okAttr {
				attribute = "all properties"
			}
		} else if classNeeded {
			objectclass, ok = classesGuidMap[guid]
		} else if attributeNeeded {
			attribute, ok = attributesGuidMap[guid]
		} else if extendedNeeded {
			extended, ok = controlAccessRightMap[guid]
		} else if validatedNeeded {
			validated, ok = attributesGuidMap[guid]
			if !ok {
				validated, ok = controlAccessRightMap[guid]
			}
		}

		if !ok {
			objectclass = guid
			attribute = guid
			extended = guid
			validated = guid
		}
	} else {
		objectclass = "all child"
		attribute = "all properties"
		extended = " all extended rights"
		validated = "all validated rights"
	}

	if checkRightExact(mask, accessRightsMap["GENERIC_ALL"]) { // 0x000F01FF
		return []string{"Full control"}, 3
	}

	var rightsSeverity int = 0
	var readableRights []string

	specificChildPermission := combinePerms(
		[]int{
			accessRightsMap["RIGHT_DS_CREATE_CHILD"], // 0x01
			accessRightsMap["RIGHT_DS_DELETE_CHILD"], // 0x02
		},
		[]string{"create", "delete"},
		mask,
	)

	specificPermission := combinePerms(
		[]int{
			accessRightsMap["RIGHT_DS_READ_PROPERTY"],  // 0x10
			accessRightsMap["RIGHT_DS_WRITE_PROPERTY"], // 0x20
		},
		[]string{"read", "write"},
		mask,
	)

	genericPermission := combinePerms(
		[]int{
			accessRightsMap["GENERIC_READ"],  // 0x00020094
			accessRightsMap["GENERIC_WRITE"], // 0x00020028
		},
		[]string{"read", "write"},
		mask,
	)

	changeRights := []string{
		"GENERIC_WRITE", "RIGHT_DS_CREATE_CHILD",
		"RIGHT_DS_DELETE_CHILD", "RIGHT_DS_WRITE_PROPERTY",
	}

	for _, changeRight := range changeRights {
		if checkRightExact(mask, accessRightsMap[changeRight]) {
			rightsSeverity = 1
		}
	}

	if validatedNeeded || extendedNeeded {
		rightsSeverity = 2
	}

	if genericPermission != "" {
		readableRights = append(readableRights, genericPermission)
	} else if specificPermission != "" {
		readableRights = append(readableRights, specificPermission+" "+attribute)
	} else if specificChildPermission != "" {
		readableRights = append(readableRights, specificChildPermission+" "+objectclass+" objects")
	}

	if checkRight(mask, accessRightsMap["RIGHT_DS_LIST_CONTENTS"]) { // 0x04
		readableRights = append(readableRights, "List contents")
	}

	if checkRight(mask, accessRightsMap["RIGHT_DS_SELF"]) { // 0x08
		readableRights = append(readableRights, "Validated write "+validated)
	}

	if checkRight(mask, accessRightsMap["RIGHT_DS_DELETE_TREE"]) { // 0x40
		readableRights = append(readableRights, "Delete tree")
	}

	if checkRight(mask, accessRightsMap["RIGHT_DS_LIST_OBJECT"]) { // 0x80
		readableRights = append(readableRights, "List object")
	}

	if specificPermission == "" && checkRight(mask, accessRightsMap["RIGHT_DS_CONTROL_ACCESS"]) { // 0x100
		readableRights = append(readableRights, extended)
	}

	if checkRight(mask, accessRightsMap["RIGHT_DELETE"]) { // 0x10000
		readableRights = append(readableRights, "Delete")
	}

	if checkRight(mask, accessRightsMap["RIGHT_READ_CONTROL"]) { // 0x20000
		readableRights = append(readableRights, "Read control")
	}

	if checkRight(mask, accessRightsMap["RIGHT_WRITE_DACL"]) { // 0x40000
		readableRights = append(readableRights, "Write DACL")
	}

	if checkRight(mask, accessRightsMap["RIGHT_WRITE_OWNER"]) { // 80000
		readableRights = append(readableRights, "Write owner")
	}

	return readableRights, rightsSeverity
}

func aceFlagsToText(flagsStr string, guidStr string) string {
	propagationString := ""
	flags := hexToInt(flagsStr)
	objectClassStr := ""
	if guidStr != "" {
		objectClassStr = classesGuidMap[guidStr] + " "
	}

	if flags&aceFlagsMap["CONTAINER_INHERIT_ACE"] == 0 {
		return "This object only"
	}

	if flags&aceFlagsMap["INHERIT_ONLY_ACE"] == 0 {
		propagationString = "this object and "
	}

	if flags&aceFlagsMap["NO_PROPAGATE_INHERIT_ACE"] == 0 {
		propagationString += "all descendant " + objectClassStr + "objects"
	} else {
		propagationString += "descendant " + objectClassStr + "objects"
	}

	return capitalize(propagationString)
}

func ParseSD(conn *ldap.Conn, baseDN string, SD string) (acesList []ACESList, owner string) {
	header := getHeader(SD)
	ACLHeader := getACLHeader(SD)
	DACL := getDACL(header, SD)
	rawACES := DACL[16:]
	aceCount, _ := strconv.Atoi(hexToDecimalString(ACLHeader.ACECount))
	rawACESList := make([]string, aceCount)

	aclOwner := getOwner(header, SD)

	for i := 0; i < aceCount; i++ {
		rawACESList[i] = getACE(rawACES)
		rawACES = rawACES[len(rawACESList[i]):]
	}

	translatedAces := []ACESList{}
	for ace, _ := range rawACESList {
		aceHeader := getACEHeader(rawACESList[ace])
		aceType, _ := strconv.Atoi(aceHeader.ACEType)

		var resolvedACEType string
		for entry, _ := range aceTypeMap {
			if entry == aceType {
				resolvedACEType = aceTypeMap[entry]
			}
		}

		entry := ACESList{SamAccountName: "", Type: "", Inheritance: false, Scope: "This object only", Severity: 0}

		switch resolvedACEType {
		case "ACCESS_ALLOWED_ACE_TYPE":
			ACE := new(ACCESS_ALLOWED_ACE)
			ACE.parse(rawACESList[ace], baseDN, conn)

			entry.Type = "Allow"
			entry.SamAccountName = ACE.samAccountName
			permissions := hexToInt(ACE.mask)

			entry.RawMask = permissions
			entry.Mask, entry.Severity = AceMaskToText(permissions, "")

			translatedAces = append(translatedAces, entry)
		case "ACCESS_ALLOWED_OBJECT_ACE_TYPE":
			ACE := new(ACCESS_ALLOWED_OBJECT_ACE)
			ACE.parse(rawACESList[ace], baseDN, conn)

			entry.Type = "Allow"
			entry.SamAccountName = ACE.samAccountName
			permissions := hexToInt(ACE.mask)
			entry.RawMask = permissions
			entry.Mask, entry.Severity = AceMaskToText(permissions, ACE.objectType)

			ACEFlags := hexToInt(ACE.header.ACEFlags)
			if ACEFlags&aceFlagsMap["INHERITED_ACE"] != 0 {
				entry.Inheritance = true
			}

			entry.Scope = aceFlagsToText(ACE.header.ACEFlags, ACE.inheritedObjectType)

			translatedAces = append(translatedAces, entry)
		case "ACCESS_DENIED_ACE_TYPE":
			ACE := new(ACCESS_DENIED_ACE)
			ACE.parse(rawACESList[ace], baseDN, conn)

			entry.Type = "Deny"
			entry.SamAccountName = ACE.samAccountName
			permissions := hexToInt(ACE.mask)
			entry.RawMask = permissions
			entry.Mask, _ = AceMaskToText(int(permissions), "")

			translatedAces = append(translatedAces, entry)
		case "ACCESS_DENIED_OBJECT_ACE_TYPE":
			ACE := new(ACCESS_DENIED_OBJECT_ACE)
			ACE.parse(rawACESList[ace], baseDN, conn)

			entry.Type = "Deny"
			entry.SamAccountName = ACE.samAccountName
			permissions := hexToInt(ACE.mask)
			entry.RawMask = permissions
			entry.Mask, _ = AceMaskToText(permissions, ACE.objectType)

			ACEFlags := hexToInt(ACE.header.ACEFlags)
			if ACEFlags&aceFlagsMap["INHERITED_ACE"] != 0 {
				entry.Inheritance = true
			}

			entry.Scope = aceFlagsToText(ACE.header.ACEFlags, ACE.inheritedObjectType)

			translatedAces = append(translatedAces, entry)
		default:
			//fmt.Println(resolvedACEType)
		}
	}

	ownerName, _ := LookupSID(conn, baseDN, aclOwner)

	return translatedAces, ownerName
}
