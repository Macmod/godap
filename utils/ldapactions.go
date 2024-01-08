package utils

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

// Reference: https://gist.github.com/Project0/61c13130563cf7f595e031d54fe55aab
const (
	ldapAttrAccountName                        = "sAMAccountName"
	ldapAttrDN                                 = "dn"
	ldapAttrUAC                                = "userAccountControl"
	ldapAttrUPN                                = "userPrincipalName" // username@logon.domain
	ldapAttrEmail                              = "mail"
	ldapAttrUnicodePw                          = "unicodePwd"
	controlTypeLdapServerPolicyHints           = "1.2.840.113556.1.4.2239"
	controlTypeLdapServerPolicyHintsDeprecated = "1.2.840.113556.1.4.2066"
)

type (
	// ldapControlServerPolicyHints implements ldap.Control
	ldapControlServerPolicyHints struct {
		oid string
	}
)

func (c *ldapControlServerPolicyHints) GetControlType() string {
	return c.oid
}

func (c *ldapControlServerPolicyHints) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Control Type (LDAP_SERVER_POLICY_HINTS_OID)"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Policy Hints)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PolicyHintsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "Flags"))
	p2.AppendChild(seq)
	packet.AppendChild(p2)

	return packet
}

func (c *ldapControlServerPolicyHints) String() string {
	return "Enforce password history policies during password set: " + c.GetControlType()
}

// User Passwords
func LDAPResetPassword(conn *ldap.Conn, objectDN string, newPassword string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", newPassword))
	if err != nil {
		return err
	}

	controlTypes, err := getSupportedControl(conn)
	if err != nil {
		return err
	}
	control := []ldap.Control{}
	for _, oid := range controlTypes {
		if oid == controlTypeLdapServerPolicyHints || oid == controlTypeLdapServerPolicyHintsDeprecated {
			control = append(control, &ldapControlServerPolicyHints{oid: oid})
			break
		}
	}

	passReq := ldap.NewModifyRequest(objectDN, control)
	passReq.Replace(ldapAttrUnicodePw, []string{pwdEncoded})
	return conn.Modify(passReq)
}

func getSupportedControl(conn ldap.Client) ([]string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	return res.Entries[0].GetAttributeValues("supportedControl"), nil
}

// Old version of LDAPResetPassword
/*
func LDAPChangePassword(conn *ldap.Conn, targetDN string, oldPassword string, newPassword string) error {
    var err error

	passwordModifyRequest := ldap.NewPasswordModifyRequest(targetDN, oldPassword, newPassword)

	_, err = conn.PasswordModify(passwordModifyRequest)
	if err != nil {
		return err
	}

	return nil
}
*/

// Objects
func LDAPDeleteObject(conn *ldap.Conn, targetDN string) error {
	var err error

	deleteRequest := ldap.NewDelRequest(targetDN, nil)

	err = conn.Del(deleteRequest)
	if err != nil {
		return err
	}

	return nil
}

func LDAPAddGroup(conn *ldap.Conn, objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "group"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})

	return conn.Add(addRequest)
}

func LDAPAddOrganizationalUnit(conn *ldap.Conn, objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("OU="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "organizationalUnit"})
	addRequest.Attribute("ou", []string{objectName})

	return conn.Add(addRequest)
}

func LDAPAddContainer(conn *ldap.Conn, objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "container"})

	return conn.Add(addRequest)
}

func LDAPAddComputer(conn *ldap.Conn, objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "computer"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})

	return conn.Add(addRequest)
}

func LDAPAddUser(conn *ldap.Conn, objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})
	rootFQDN, err := FindRootFQDN(conn)

	if err == nil {
		userPrincipalName := fmt.Sprintf("%s@%s", objectName, strings.ToLower(rootFQDN))
		addRequest.Attribute(
			"userPrincipalName",
			[]string{userPrincipalName},
		)
	}

	return conn.Add(addRequest)
}

// Attributes
func LDAPAddAttribute(conn *ldap.Conn, targetDN string, attributeToAdd string, attributeValues []string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Add(attributeToAdd, attributeValues)

	err = conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func LDAPModifyAttribute(conn *ldap.Conn, targetDN string, attributeToModify string, attributeValues []string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Replace(attributeToModify, attributeValues)

	err = conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func LDAPDeleteAttribute(conn *ldap.Conn, targetDN string, attributeToDelete string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Delete(attributeToDelete, []string{})

	err = conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

// Search
func FindRootDN(conn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) < 1 {
		return "", fmt.Errorf("No entries found")
	}

	rootDN := searchResult.Entries[0].GetAttributeValue("namingContexts")

	return rootDN, nil
}

func FindRootFQDN(conn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"ldapServiceName"},
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) == 0 {
		return "", fmt.Errorf("ldapServiceName attribute not found")
	}

	ldapSN := searchResult.Entries[0].GetAttributeValue("ldapServiceName")
	ldapSNTokens := strings.Split(ldapSN, "@")
	dnsRoot := ldapSNTokens[1]

	return dnsRoot, nil
}
