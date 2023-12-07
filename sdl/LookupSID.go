package sdl

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func LookupSID(conn *ldap.Conn, baseDN string, SID string) (resolvedSID string, err error) {
	for entry, _ := range wellKnownSIDsMap {
		if SID == entry {
			return wellKnownSIDsMap[entry], nil
		}
	}

	query := fmt.Sprintf("(objectSID=%s)", SID)
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, 0, 0, 0, false,
		query,
		[]string{},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
        return "", err
	}

	if len(result.Entries) > 0 {
		resolvedSID = result.Entries[0].GetAttributeValues("sAMAccountName")[0]
        return resolvedSID, nil
	}

	return "", fmt.Errorf("No entries found")
}
