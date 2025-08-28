package sdl

import (
	"fmt"
	"strconv"

	"github.com/Macmod/godap/v2/pkg/ldaputils"
)

// ACL
type ACL struct {
	Header *ACLHEADER
	Aces   []ACEInt
}

func (acl *ACL) Parse(aclStr string) {
	acl.Header = getACLHeader(aclStr[:16])
	rawACES := aclStr[16:]

	aceCount, _ := strconv.Atoi(ldaputils.HexToDecimalString(ldaputils.EndianConvert(acl.Header.ACECount)))
	rawACESList := make([]string, aceCount)

	for i := 0; i < aceCount; i++ {
		rawACESList[i] = getACE(rawACES)
		rawACES = rawACES[len(rawACESList[i]):]
	}

	var resolvedACEType string
	for ace := range rawACESList {
		aceHeader := newACEHeader(rawACESList[ace])
		aceType, _ := strconv.Atoi(aceHeader.ACEType)

		for entry := range AceTypeMap {
			if entry == aceType {
				resolvedACEType = AceTypeMap[entry]
			}
		}

		var ACE ACEInt
		switch resolvedACEType {
		case "ACCESS_ALLOWED_ACE_TYPE", "ACCESS_DENIED_ACE_TYPE":
			ACE = new(BASIC_ACE)
			ACE.Parse(rawACESList[ace])
		case "ACCESS_ALLOWED_OBJECT_ACE_TYPE", "ACCESS_DENIED_OBJECT_ACE_TYPE":
			ACE = new(OBJECT_ACE)
			ACE.Parse(rawACESList[ace])
		default:
			ACE = new(NOTIMPL_ACE)
			ACE.Parse(rawACESList[ace])
		}

		acl.Aces = append(acl.Aces, ACE)
	}
}

func (acl *ACL) Encode() string {
	if len(acl.Aces) == 0 {
		return ""
	}

	s := acl.Header.Encode()
	for _, ace := range acl.Aces {
		s += ace.Encode()
	}

	return s
}

// SD HEADER
type HEADER struct {
	Revision    string
	Sbz1        string
	Control     string
	OffsetOwner string
	OffsetGroup string
	OffsetSacl  string
	OffsetDacl  string
}

func NewHeader(sdStr string) *HEADER {
	header := new(HEADER)

	header.Revision = sdStr[0:2]
	header.Sbz1 = sdStr[2:4]
	header.Control = sdStr[4:8]
	header.OffsetOwner = sdStr[8:16]
	header.OffsetGroup = sdStr[16:24]
	header.OffsetSacl = sdStr[24:32]
	header.OffsetDacl = sdStr[32:40]

	return header
}

func (header *HEADER) Encode() string {
	s := header.Revision
	s += header.Sbz1
	s += header.Control
	s += header.OffsetOwner
	s += header.OffsetGroup
	s += header.OffsetSacl
	s += header.OffsetDacl
	return s
}

// SecurityDescriptor
type SecurityDescriptor struct {
	Header *HEADER
	SACL   *ACL
	DACL   *ACL
	Owner  string
	Group  string
}

func NewSD(sdStr string) *SecurityDescriptor {
	if len(sdStr) < 40 {
		return nil
	}

	sd := new(SecurityDescriptor)

	sd.Header = NewHeader(sdStr)

	sd.Owner = ""
	sd.Group = ""

	ownerOffset := int(ldaputils.HexToOffset(sd.Header.OffsetOwner))
	ownerLen := ldaputils.HexToInt(sdStr[ownerOffset+2:ownerOffset+4])*2*4 + 16
	if int(ownerOffset+ownerLen) <= len(sdStr) {
		sd.Owner = sdStr[ownerOffset : ownerOffset+ownerLen]
	}

	groupOffset := int(ldaputils.HexToOffset(sd.Header.OffsetGroup))
	groupLen := ldaputils.HexToInt(sdStr[groupOffset+2:groupOffset+4])*2*4 + 16
	if int(groupOffset+groupLen) <= len(sdStr) {
		sd.Group = sdStr[groupOffset : groupOffset+groupLen]
	}

	// SACL
	sd.SACL = new(ACL)
	saclOffset := ldaputils.HexToOffset(sd.Header.OffsetSacl)
	if saclOffset != 0 {
		sd.SACL.Parse(sdStr[saclOffset:])
	}

	// DACL
	sd.DACL = new(ACL)
	daclOffset := ldaputils.HexToOffset(sd.Header.OffsetDacl)
	if daclOffset != 0 {
		sd.DACL.Parse(sdStr[daclOffset:])
	}

	return sd
}

func (sd *SecurityDescriptor) updateMetadata() {
	sd.DACL.Header.ACECount = ldaputils.EndianConvert(fmt.Sprintf("%04x", len(sd.DACL.Aces)))

	mainDaclPart := sd.Header.Encode() + sd.SACL.Encode() + sd.DACL.Encode()
	sd.Header.OffsetOwner = ldaputils.EndianConvert(fmt.Sprintf("%08x", int(len(mainDaclPart)/2)))
	sd.Header.OffsetGroup = ldaputils.EndianConvert(fmt.Sprintf("%08x", int(len(mainDaclPart+sd.Owner)/2)))

	sd.DACL.Header.ACLSizeBytes = ldaputils.EndianConvert(fmt.Sprintf("%04x", len(sd.DACL.Encode())/2))
}

func (sd *SecurityDescriptor) GetControl() int {
	return ldaputils.HexToInt(ldaputils.EndianConvert(sd.Header.Control))
}

func (sd *SecurityDescriptor) SetControl(control int) {
	sd.Header.Control = ldaputils.EndianConvert(fmt.Sprintf("%04x", control))
}

func (sd *SecurityDescriptor) SetOwnerAndGroup(ownerSID string, groupSID string) {
	sd.Owner = ownerSID
	sd.Group = groupSID

	sd.updateMetadata()
}

func (sd *SecurityDescriptor) SetDaclACES(aces []ACEInt) {
	sd.DACL.Aces = aces
	sd.updateMetadata()
}

func (sd *SecurityDescriptor) Encode() string {
	sdStr := sd.Header.Encode() + sd.SACL.Encode() + sd.DACL.Encode() + sd.Owner + sd.Group
	return sdStr
}

// ACL Header
type ACLHEADER struct {
	ACLRevision  string
	Sbz1         string
	ACLSizeBytes string
	ACECount     string
	Sbz2         string
}

func getACLHeader(ACL string) *ACLHEADER {
	ACLHeader := new(ACLHEADER)
	ACLHeader.ACLRevision = ACL[0:2]
	ACLHeader.Sbz1 = ACL[2:4]
	ACLHeader.ACLSizeBytes = ACL[4:8]
	ACLHeader.ACECount = ACL[8:12]
	ACLHeader.Sbz2 = ACL[12:16]

	return ACLHeader
}

func (aclheader *ACLHEADER) Encode() string {
	s := aclheader.ACLRevision
	s += aclheader.Sbz1
	s += aclheader.ACLSizeBytes
	s += aclheader.ACECount
	s += aclheader.Sbz2
	return s
}
