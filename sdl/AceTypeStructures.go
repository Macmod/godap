package sdl

import "github.com/go-ldap/ldap/v3"

type ACCESS_ALLOWED_ACE struct {
	header         *ACEHEADER
	mask           string
	SID            string
	samAccountName string
}

func (ace *ACCESS_ALLOWED_ACE) parse(rawACE string, baseDN string, conn *ldap.Conn) {
	ace.header = getACEHeader(rawACE)
	ace.mask = getACEMask(rawACE)
	ace.SID = convertSID(rawACE[16:])
	ace.samAccountName, _ = LookupSID(conn, baseDN, ace.SID)
}

type ACCESS_ALLOWED_OBJECT_ACE struct {
	header              *ACEHEADER
	mask                string
	flags               string
	objectType          string
	inheritedObjectType string
	SID                 string
	samAccountName      string
}

func (ace *ACCESS_ALLOWED_OBJECT_ACE) parse(rawACE string, baseDN string, conn *ldap.Conn) {
	ace.header = getACEHeader(rawACE)
	ace.mask = getACEMask(rawACE)
	ace.flags = getACEFlags((rawACE))
	ace.objectType, ace.inheritedObjectType = getObjectAndInheritedType(rawACE, ace.flags)
	lengthBeforeSID := 24
	if len(ace.objectType) > 0 {
		lengthBeforeSID += 32
	}
	if len(ace.inheritedObjectType) > 0 {
		lengthBeforeSID += 32
	}
	ace.SID = convertSID(rawACE[lengthBeforeSID:])
	ace.samAccountName, _ = LookupSID(conn, baseDN, ace.SID)
}

type ACCESS_DENIED_ACE struct {
	header         *ACEHEADER
	mask           string
	SID            string
	samAccountName string
}

func (ace *ACCESS_DENIED_ACE) parse(rawACE string, baseDN string, conn *ldap.Conn) {
	ace.header = getACEHeader(rawACE)
	ace.mask = getACEMask(rawACE)
	ace.SID = convertSID(rawACE[16:])
	ace.samAccountName, _ = LookupSID(conn, baseDN, ace.SID)
}

type ACCESS_DENIED_OBJECT_ACE struct {
	header              *ACEHEADER
	mask                string
	flags               string
	objectType          string
	inheritedObjectType string
	SID                 string
	samAccountName      string
}

func (ace *ACCESS_DENIED_OBJECT_ACE) parse(rawACE string, baseDN string, conn *ldap.Conn) {
	ace.header = getACEHeader(rawACE)
	ace.mask = getACEMask(rawACE)
	ace.flags = getACEFlags((rawACE))
	ace.objectType, ace.inheritedObjectType = getObjectAndInheritedType(rawACE, ace.flags)
	lengthBeforeSID := 24
	if len(ace.objectType) > 0 {
		lengthBeforeSID += 32
	}
	if len(ace.inheritedObjectType) > 0 {
		lengthBeforeSID += 32
	}
	ace.SID = convertSID(rawACE[lengthBeforeSID:])
	ace.samAccountName, _ = LookupSID(conn, baseDN, ace.SID)
}

// The ACE types below seem currently useless,
// if I figure out any use for them in the future I'll
// consider implementing some additional logic
type ACCESS_ALLOWED_CALLBACK_ACE struct {
	header          string
	mask            string
	SID             string
	applicationData string
}

type ACCESS_DENIED_CALLBACK_ACE struct {
	header          string
	mask            string
	SID             string
	applicationData string
}

type ACCESS_ALLOWED_CALLBACK_OBJECT_ACE struct {
	header              string
	mask                string
	flags               string
	objectType          string
	inheritedObjectType string
	SID                 string
	applicationData     string
}

type ACCESS_DENIED_CALLBACK_OBJECT_ACE struct {
	header              string
	mask                string
	flags               string
	objectType          string
	inheritedObjectType string
	SID                 string
	applicationData     string
}

type SYSTEM_AUDIT_ACE struct {
	header string
	mask   string
	SID    string
}

type SYSTEM_AUDIT_OBJECT_ACE struct {
	header              string
	mask                string
	flags               string
	objectType          string
	inheritedObjectType string
	SID                 string
	applicationData     string
}

type SYSTEM_AUDIT_CALLBACK_ACE struct {
	header          string
	mask            string
	SID             string
	applicationData string
}

type SYSTEM_MANDATORY_LABEL_ACE struct {
	header string
	mask   string
	SID    string
}

type SYSTEM_AUDIT_CALLBACK_OBJECT_ACE struct {
	header              string
	mask                string
	flags               string
	objectType          string
	inheritedObjectType string
	SID                 string
	applicationData     string
}

type SYSTEM_RESOURCE_ATTRIBUTE_ACE struct {
	header        string
	mask          string
	SID           string
	attributeData string
}

type SYSTEM_SCOPED_POLICY_ID_ACE struct {
	header string
	mask   string
	SID    string
}
