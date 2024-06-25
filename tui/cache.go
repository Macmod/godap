package tui

import (
	"regexp"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

type EntryCache struct {
	entries map[string]*ldap.Entry
	lock    sync.Mutex
}

func (sc *EntryCache) Delete(key string) {
	sc.lock.Lock()
	delete(sc.entries, key)
	sc.lock.Unlock()
}

func (sc *EntryCache) Clear() {
	sc.lock.Lock()
	clear(sc.entries)
	sc.lock.Unlock()
}

func (sc *EntryCache) Add(key string, val *ldap.Entry) {
	sc.lock.Lock()
	sc.entries[key] = val
	sc.lock.Unlock()
}

func (sc *EntryCache) Get(key string) (*ldap.Entry, bool) {
	sc.lock.Lock()
	defer sc.lock.Unlock()
	entry, ok := sc.entries[key]
	return entry, ok
}

func (sc *EntryCache) Length() int {
	sc.lock.Lock()
	defer sc.lock.Unlock()
	return len(sc.entries)
}

type EntryMatch struct {
	MatchField      string
	MatchDN         string
	MatchAttrName   string
	MatchAttrVal    string
	MatchAttrValIdx int
	MatchPosBegin   int
	MatchPosEnd     int
}

func (sc *EntryCache) FindWithRegexp(needle *regexp.Regexp) []EntryMatch {
	sc.lock.Lock()
	defer sc.lock.Unlock()

	var match []int

	results := []EntryMatch{}
	for dn, entry := range sc.entries {
		match = needle.FindStringIndex(dn)
		if match != nil {
			results = append(results, EntryMatch{
				"ObjectDN", dn, "", "", -1, match[0], match[1],
			})
		}

		for _, attr := range entry.Attributes {
			attrName := attr.Name
			match = needle.FindStringIndex(attrName)
			if match != nil {
				results = append(results, EntryMatch{
					"AttrName", dn, attrName, "", -1, match[0], match[1],
				})
			}

			for idx, attrValue := range attr.Values {
				match = needle.FindStringIndex(attrValue)
				if match != nil {
					results = append(results, EntryMatch{
						"AttrVal", dn, attrName, attrValue, idx, match[0], match[1],
					})
				}
			}
		}
	}

	return results
}
