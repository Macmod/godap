package utils

import (
	"crypto/tls"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
)

// Basic LDAP connection type
type LDAPConn struct {
	Conn *ldap.Conn
}

func (lc LDAPConn) UpgradeToTLS(tlsConfig *tls.Config) error {
	if lc.Conn == nil {
		return fmt.Errorf("Current connection is invalid")
	}

	err := lc.Conn.StartTLS(tlsConfig)
	if err != nil {
		return err
	}

	return nil
}

func NewLDAPConn(ldapServer string, ldapPort int, ldaps bool, tlsConfig *tls.Config) (*LDAPConn, error) {
	var conn *ldap.Conn
	var err error

	if ldaps {
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort), tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
	}

	if err != nil {
		return nil, err
	}

	return &LDAPConn{
		Conn: conn,
	}, nil
}

func (lc LDAPConn) LDAPBind(ldapUsername string, ldapPassword string) error {
	err := lc.Conn.Bind(ldapUsername, ldapPassword)
	return err
}

func (lc LDAPConn) NTLMBindWithHash(ntlmDomain string, ntlmUsername string, ntlmHash string) error {
	err := lc.Conn.NTLMBindWithHash(ntlmDomain, ntlmUsername, ntlmHash)
	return err
}

// Search
func (lc LDAPConn) Query(baseDN string, searchFilter string, scope int) ([]*ldap.Entry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{},
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	return sr.Entries, nil
}

func (lc LDAPConn) FindRootDN() (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"namingContexts"},
		nil,
	)

	searchResult, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(searchResult.Entries) < 1 {
		return "", fmt.Errorf("No entries found")
	}

	rootDN := searchResult.Entries[0].GetAttributeValue("namingContexts")

	return rootDN, nil
}

func (lc LDAPConn) FindRootFQDN() (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"ldapServiceName"},
		nil,
	)

	searchResult, err := lc.Conn.Search(searchRequest)
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

func (lc LDAPConn) QueryGroupMembers(groupName string, rootDN string) (group []*ldap.Entry, err error) {
	groupDNQuery := fmt.Sprintf("(&(objectCategory=group)(sAMAccountName=%s))", groupName)

	groupDN := groupName
	if !strings.Contains(groupName, ",") {
		groupSearch := ldap.NewSearchRequest(
			rootDN,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			groupDNQuery,
			[]string{"distinguishedName"},
			nil,
		)

		groupResult, err := lc.Conn.Search(groupSearch)
		if err != nil {
			return nil, err
		}

		if len(groupResult.Entries) == 0 {
			return nil, fmt.Errorf("Group '%s' not found", groupName)
		}

		groupDN = groupResult.Entries[0].GetAttributeValue("distinguishedName")
	}

	ldapQuery := fmt.Sprintf("(memberOf=%s)", groupDN)

	search := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapQuery,
		[]string{"sAMAccountName", "objectCategory"},
		nil,
	)

	result, err := lc.Conn.Search(search)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("Group '%s' not found", groupName)
	}

	return result.Entries, nil
}

func (lc LDAPConn) QueryUserGroups(userName string, rootDN string) ([]*ldap.Entry, error) {
	var ldapQuery string
	if !strings.Contains(userName, ",") {
		ldapQuery = fmt.Sprintf("(sAMAccountName=%s)", userName)
	} else {
		ldapQuery = fmt.Sprintf("(distinguishedName=%s)", userName)
	}

	search := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapQuery,
		[]string{"memberOf"},
		nil,
	)

	result, err := lc.Conn.Search(search)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("User '%s' not found", userName)
	}

	return result.Entries, nil
}

// User Passwords
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

func (lc LDAPConn) ResetPassword(objectDN string, newPassword string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", newPassword))
	if err != nil {
		return err
	}

	controlTypes, err := getSupportedControl(lc.Conn)
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
	return lc.Conn.Modify(passReq)
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
func (lc LDAPConn) DeleteObject(targetDN string) error {
	var err error

	deleteRequest := ldap.NewDelRequest(targetDN, nil)

	err = lc.Conn.Del(deleteRequest)
	if err != nil {
		return err
	}

	return nil
}

func (lc LDAPConn) AddGroup(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "group"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})

	return lc.Conn.Add(addRequest)
}

func (lc LDAPConn) AddOrganizationalUnit(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("OU="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "organizationalUnit"})
	addRequest.Attribute("ou", []string{objectName})

	return lc.Conn.Add(addRequest)
}

func (lc LDAPConn) AddContainer(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "container"})

	return lc.Conn.Add(addRequest)
}

func (lc LDAPConn) AddComputer(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "computer"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName + "$"})
	addRequest.Attribute("userAccountControl", []string{"4096"})

	return lc.Conn.Add(addRequest)
}

func (lc LDAPConn) AddUser(objectName string, parentDN string) error {
	addRequest := ldap.NewAddRequest("CN="+objectName+","+parentDN, nil)
	addRequest.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addRequest.Attribute("cn", []string{objectName})
	addRequest.Attribute("sAMAccountName", []string{objectName})
	rootFQDN, err := lc.FindRootFQDN()

	if err == nil {
		userPrincipalName := fmt.Sprintf("%s@%s", objectName, strings.ToLower(rootFQDN))
		addRequest.Attribute(
			"userPrincipalName",
			[]string{userPrincipalName},
		)
	}

	return lc.Conn.Add(addRequest)
}

// Attributes
func (lc LDAPConn) AddAttribute(targetDN string, attributeToAdd string, attributeValues []string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Add(attributeToAdd, attributeValues)

	err = lc.Conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (lc LDAPConn) ModifyAttribute(targetDN string, attributeToModify string, attributeValues []string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Replace(attributeToModify, attributeValues)

	err = lc.Conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (lc LDAPConn) DeleteAttribute(targetDN string, attributeToDelete string) error {
	var err error

	modifyRequest := ldap.NewModifyRequest(targetDN, nil)
	modifyRequest.Delete(attributeToDelete, []string{})

	err = lc.Conn.Modify(modifyRequest)
	if err != nil {
		return err
	}

	return nil
}
