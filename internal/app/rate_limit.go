package app

import (
	"container/list"
	"sync"
	"time"
)

const (
	defaultMaxRateLimitEntries = 100_000
	maxRateLimitCleanupBatch   = 1024
)

type requestLimiter struct {
	mu          sync.Mutex
	requests    int
	window      time.Duration
	entries     map[string]*rateLimitEntry
	order       *list.List
	resetOrder  *list.List
	nextCleanup time.Time
	maxEntries  int
}

type rateLimitEntry struct {
	count        int
	reset        time.Time
	lastSeen     time.Time
	element      *list.Element
	resetElement *list.Element
}

func newRequestLimiter(cfg RateLimitBucketConfig) *requestLimiter {
	if cfg.Requests <= 0 || cfg.Window <= 0 {
		return nil
	}
	return &requestLimiter{
		requests:   cfg.Requests,
		window:     cfg.Window,
		entries:    map[string]*rateLimitEntry{},
		order:      list.New(),
		resetOrder: list.New(),
		maxEntries: defaultMaxRateLimitEntries,
	}
}

func (l *requestLimiter) allow(key string, now time.Time) (allowed bool, retryAfter int, capacityLimited bool) {
	if l == nil {
		return true, 0, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.cleanup(now)
	entry := l.entries[key]
	if entry == nil || !now.Before(entry.reset) {
		if entry == nil && len(l.entries) >= l.maxEntries {
			l.cleanupResetExpired(now, maxRateLimitCleanupBatch)
			if len(l.entries) >= l.maxEntries {
				retryAt := now.Add(l.window)
				if front := l.resetOrder.Front(); front != nil {
					retryAt = front.Value.(*rateLimitEntry).reset
				}
				return false, retryAfterSeconds(retryAt, now), true
			}
		}
		if entry == nil {
			entry = &rateLimitEntry{}
			entry.element = l.order.PushBack(key)
			l.entries[key] = entry
		} else {
			l.order.MoveToBack(entry.element)
			l.resetOrder.Remove(entry.resetElement)
		}
		entry.count = 1
		entry.reset = now.Add(l.window)
		entry.lastSeen = now
		entry.resetElement = l.resetOrder.PushBack(entry)
		return true, 0, false
	}

	entry.lastSeen = now
	l.order.MoveToBack(entry.element)
	if entry.count >= l.requests {
		return false, retryAfterSeconds(entry.reset, now), false
	}
	entry.count++
	return true, 0, false
}

func (l *requestLimiter) cleanupResetExpired(now time.Time, limit int) {
	for range limit {
		front := l.resetOrder.Front()
		if front == nil {
			return
		}
		entry := front.Value.(*rateLimitEntry)
		if now.Before(entry.reset) {
			return
		}
		key := entry.element.Value.(string)
		l.removeEntry(key, entry)
	}
}

func (l *requestLimiter) cleanup(now time.Time) {
	if !l.nextCleanup.IsZero() && now.Before(l.nextCleanup) {
		return
	}
	l.cleanupExpired(now, maxRateLimitCleanupBatch)
	l.nextCleanup = now.Add(maxDuration(l.window, time.Minute))
}

func (l *requestLimiter) cleanupExpired(now time.Time, limit int) {
	staleBefore := now.Add(-maxDuration(2*l.window, 5*time.Minute))
	for range limit {
		front := l.order.Front()
		if front == nil {
			return
		}
		key := front.Value.(string)
		entry := l.entries[key]
		if !entry.lastSeen.Before(staleBefore) && now.Before(entry.reset.Add(l.window)) {
			return
		}
		l.removeEntry(key, entry)
	}
}

func (l *requestLimiter) removeEntry(key string, entry *rateLimitEntry) {
	delete(l.entries, key)
	l.order.Remove(entry.element)
	l.resetOrder.Remove(entry.resetElement)
}

func retryAfterSeconds(reset time.Time, now time.Time) int {
	remaining := reset.Sub(now)
	if remaining <= 0 {
		return 1
	}
	return int((remaining + time.Second - 1) / time.Second)
}

func maxDuration(a time.Duration, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
