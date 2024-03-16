package main

import (
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
