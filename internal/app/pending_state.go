package app

import (
	"container/list"
	"sync"
	"time"
)

const (
	defaultMaxPendingStates           = 100_000
	defaultMaxPendingStatesPerSession = 8
	maxPendingStateCleanupBatch       = 1024
)

type pendingStateStore struct {
	mu            sync.Mutex
	entries       map[string]*pendingStateEntry
	globalOrder   *list.List
	sessionOrders map[string]*list.List
	maxEntries    int
	maxPerSession int
}

type pendingStateAddResult int

const (
	pendingStateAdded pendingStateAddResult = iota
	pendingStateSessionEvicted
	pendingStateAtCapacity
)

type pendingStateEntry struct {
	key            string
	sessionID      string
	expires        time.Time
	globalElement  *list.Element
	sessionElement *list.Element
}

func newPendingStateStore() *pendingStateStore {
	return &pendingStateStore{
		entries:       make(map[string]*pendingStateEntry),
		globalOrder:   list.New(),
		sessionOrders: make(map[string]*list.List),
		maxEntries:    defaultMaxPendingStates,
		maxPerSession: defaultMaxPendingStatesPerSession,
	}
}

func (s *pendingStateStore) add(sessionID string, verifier string, expires time.Time, now time.Time) pendingStateAddResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup(now, maxPendingStateCleanupBatch)

	key := pendingStateKey(sessionID, verifier)
	if existing := s.entries[key]; existing != nil {
		existing.expires = expires
		s.globalOrder.MoveToBack(existing.globalElement)
		s.sessionOrders[sessionID].MoveToBack(existing.sessionElement)
		return pendingStateAdded
	}
	sessionOrder := s.sessionOrders[sessionID]
	if sessionOrder == nil {
		sessionOrder = list.New()
		s.sessionOrders[sessionID] = sessionOrder
	}
	result := pendingStateAdded
	for sessionOrder.Len() >= s.maxPerSession {
		s.remove(sessionOrder.Front().Value.(*pendingStateEntry))
		result = pendingStateSessionEvicted
	}
	// A per-session limit of one can remove this session's list entirely.
	sessionOrder = s.sessionOrders[sessionID]
	if sessionOrder == nil {
		sessionOrder = list.New()
		s.sessionOrders[sessionID] = sessionOrder
	}
	if len(s.entries) >= s.maxEntries {
		if sessionOrder.Len() == 0 {
			delete(s.sessionOrders, sessionID)
		}
		return pendingStateAtCapacity
	}

	entry := &pendingStateEntry{key: key, sessionID: sessionID, expires: expires}
	entry.globalElement = s.globalOrder.PushBack(entry)
	entry.sessionElement = sessionOrder.PushBack(entry)
	s.entries[key] = entry
	return result
}

func (s *pendingStateStore) consume(sessionID string, verifier string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup(now, maxPendingStateCleanupBatch)

	entry := s.entries[pendingStateKey(sessionID, verifier)]
	if entry == nil {
		return false
	}
	if !now.Before(entry.expires) {
		s.remove(entry)
		return false
	}
	s.remove(entry)
	return true
}

func (s *pendingStateStore) cleanup(now time.Time, limit int) {
	for range limit {
		front := s.globalOrder.Front()
		if front == nil {
			return
		}
		entry := front.Value.(*pendingStateEntry)
		if now.Before(entry.expires) {
			return
		}
		s.remove(entry)
	}
}

func (s *pendingStateStore) remove(entry *pendingStateEntry) {
	delete(s.entries, entry.key)
	s.globalOrder.Remove(entry.globalElement)
	sessionOrder := s.sessionOrders[entry.sessionID]
	if sessionOrder == nil {
		return
	}
	sessionOrder.Remove(entry.sessionElement)
	if sessionOrder.Len() == 0 {
		delete(s.sessionOrders, entry.sessionID)
	}
}

func pendingStateKey(sessionID string, verifier string) string {
	return sessionID + "\x00" + verifier
}
