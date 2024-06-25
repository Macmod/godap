package sdl

import (
	"strconv"
	"strings"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
)

// References
// - http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm
// - https://www.itinsights.org/Process-low-level-NtSecurityDescriptor/
// - https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253

func getACE(rawACE string) (ACE string) {
	aceLengthBytes, _ := strconv.Atoi(ldaputils.HexToDecimalString(ldaputils.EndianConvert(rawACE[4:8])))
	aceLength := aceLengthBytes * 2
	ACE = rawACE[:aceLength]

	return
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

	return ldaputils.Capitalize(strings.Join(combined, "/"))
}

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

	classNeeded = checkRight(mask, AccessRightsMap["RIGHT_DS_CREATE_CHILD"]) || checkRight(mask, AccessRightsMap["RIGHT_DS_DELETE_CHILD"])
	attributeNeeded = checkRight(mask, AccessRightsMap["RIGHT_DS_READ_PROPERTY"]) || checkRight(mask, AccessRightsMap["RIGHT_DS_WRITE_PROPERTY"])
	extendedNeeded = checkRight(mask, AccessRightsMap["RIGHT_DS_CONTROL_ACCESS"])
	validatedNeeded = checkRight(mask, AccessRightsMap["RIGHT_DS_SELF"])

	if len(guid) > 0 {
		ok = true
		if classNeeded && attributeNeeded {
			objectclass, okClass = ClassGuids[guid]
			attribute, okAttr = AttributeGuids[guid]

			if !okClass {
				objectclass = "any class of"
			} else if !okAttr {
				attribute = "all properties"
			}
		} else if classNeeded {
			objectclass, ok = ClassGuids[guid]
		} else if attributeNeeded {
			attribute, ok = AttributeGuids[guid]
			if !ok {
				// Control rights case #2: read/write on property sets
				attribute, ok = PropertySetGuids[guid]
			}
		} else if extendedNeeded {
			// Control rights case #1: extended rights
			extended, ok = ExtendedGuids[guid]
		} else if validatedNeeded {
			// Control rights case #3: validated writes
			validated, ok = ValidatedWriteGuids[guid]
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
		validated = "All validated rights"
	}

	if checkRightExact(mask, AccessRightsMap["GENERIC_ALL"]) { // 0x000F01FF
		return []string{"Full control"}, 3
	}

	var rightsSeverity int = 0
	var readableRights []string

	specificChildPermission := combinePerms(
		[]int{
			AccessRightsMap["RIGHT_DS_CREATE_CHILD"], // 0x01
			AccessRightsMap["RIGHT_DS_DELETE_CHILD"], // 0x02
		},
		[]string{"create", "delete"},
		mask,
	)

	specificPermission := combinePerms(
		[]int{
			AccessRightsMap["RIGHT_DS_READ_PROPERTY"],  // 0x10
			AccessRightsMap["RIGHT_DS_WRITE_PROPERTY"], // 0x20
		},
		[]string{"read", "write"},
		mask,
	)

	genericPermission := combinePerms(
		[]int{
			AccessRightsMap["GENERIC_READ"],  // 0x00020094
			AccessRightsMap["GENERIC_WRITE"], // 0x00020028
		},
		[]string{"read", "write"},
		mask,
	)

	changeRights := []string{
		"GENERIC_WRITE", "RIGHT_DS_CREATE_CHILD",
		"RIGHT_DS_DELETE_CHILD", "RIGHT_DS_WRITE_PROPERTY",
	}

	for _, changeRight := range changeRights {
		if checkRightExact(mask, AccessRightsMap[changeRight]) {
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

	if checkRight(mask, AccessRightsMap["RIGHT_DS_LIST_CONTENTS"]) { // 0x04
		readableRights = append(readableRights, "List contents")
	}

	if checkRight(mask, AccessRightsMap["RIGHT_DS_SELF"]) { // 0x08
		readableRights = append(readableRights, validated)
	}

	if checkRight(mask, AccessRightsMap["RIGHT_DS_DELETE_TREE"]) { // 0x40
		readableRights = append(readableRights, "Delete tree")
	}

	if checkRight(mask, AccessRightsMap["RIGHT_DS_LIST_OBJECT"]) { // 0x80
		readableRights = append(readableRights, "List object")
	}

	if specificPermission == "" && checkRight(mask, AccessRightsMap["RIGHT_DS_CONTROL_ACCESS"]) { // 0x100
		readableRights = append(readableRights, extended)
	}

	if checkRight(mask, AccessRightsMap["RIGHT_DELETE"]) { // 0x10000
		readableRights = append(readableRights, "Delete")
	}

	if checkRight(mask, AccessRightsMap["RIGHT_READ_CONTROL"]) { // 0x20000
		readableRights = append(readableRights, "Read permissions")
	}

	if checkRight(mask, AccessRightsMap["RIGHT_WRITE_DACL"]) { // 0x40000
		readableRights = append(readableRights, "Modify permissions")
	}

	if checkRight(mask, AccessRightsMap["RIGHT_WRITE_OWNER"]) { // 80000
		readableRights = append(readableRights, "Modify owner")
	}

	return readableRights, rightsSeverity
}

func AceFlagsToText(flagsStr string, guidStr string) string {
	propagationString := ""
	flags := ldaputils.HexToInt(flagsStr)
	objectClassStr := ""
	if guidStr != "" {
		objectClassStr = ClassGuids[guidStr] + " "
	}

	if flags&AceFlagsMap["CONTAINER_INHERIT_ACE"] == 0 {
		return "This object only"
	}

	if flags&AceFlagsMap["INHERIT_ONLY_ACE"] == 0 {
		propagationString = "this object and "
	}

	if flags&AceFlagsMap["NO_PROPAGATE_INHERIT_ACE"] == 0 {
		propagationString += "all descendant " + objectClassStr + "objects"
	} else {
		propagationString += "descendant " + objectClassStr + "objects"
	}

	return ldaputils.Capitalize(propagationString)
}
