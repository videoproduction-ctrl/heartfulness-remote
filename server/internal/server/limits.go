package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate limits and lockout (PROTOCOL.md §6).
const (
	lockoutFailures   = 5
	lockoutWindow     = 15 * time.Minute
	lockoutDuration   = 15 * time.Minute
	globalFailLimit   = 50 // more than this many failures per hour…
	globalFailWindow  = time.Hour
	globalThrottleFor = time.Hour        // …throttles auth endpoints for an hour
	globalThrottleGap = 10 * time.Second // to 1 request per 10 s
	limiterIdleExpiry = time.Hour
	maxTrackedIPs     = 100_000
)

type bucket int

const (
	bucketAPI    bucket = iota // all /api/*: 5/s burst 20
	bucketAuth                 // setup/*, login/*, link/start|approve: 10/min
	bucketPoll                 // link/poll: 10/min (separate so polling cannot starve login)
	bucketWS                   // WebSocket upgrades: 10/min
	bucketStatic               // static files + /healthz: generous
	numBuckets
)

func newBucket(b bucket) *rate.Limiter {
	switch b {
	case bucketAPI:
		return rate.NewLimiter(5, 20)
	case bucketAuth, bucketPoll, bucketWS:
		return rate.NewLimiter(rate.Every(6*time.Second), 10)
	default:
		return rate.NewLimiter(50, 200)
	}
}

type ipState struct {
	buckets     [numBuckets]*rate.Limiter
	fails       []time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

type limiter struct {
	mu          sync.Mutex
	ips         map[string]*ipState
	globalFails []time.Time
	globalUntil time.Time
	global      *rate.Limiter
}

func newLimiter(now func() time.Time) *limiter {
	_ = now
	return &limiter{
		ips:    map[string]*ipState{},
		global: rate.NewLimiter(rate.Every(globalThrottleGap), 1),
	}
}

func (l *limiter) get(key string, now time.Time) *ipState {
	st, ok := l.ips[key]
	if !ok {
		if len(l.ips) >= maxTrackedIPs {
			l.cleanupLocked(now)
		}
		st = &ipState{}
		l.ips[key] = st
	}
	st.lastSeen = now
	return st
}

// allow consumes one token from the IP's bucket.
func (l *limiter) allow(key string, b bucket, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.get(key, now)
	if st.buckets[b] == nil {
		st.buckets[b] = newBucket(b)
	}
	return reserve(st.buckets[b], now)
}

func reserve(lim *rate.Limiter, now time.Time) (bool, time.Duration) {
	r := lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Minute
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// locked reports whether the IP is locked out and for how long.
func (l *limiter) locked(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.ips[key]
	if !ok || !now.Before(st.lockedUntil) {
		return false, 0
	}
	return true, st.lockedUntil.Sub(now)
}

// fail records an auth failure. It reports whether this failure locked the IP
// and whether it engaged the global throttle.
func (l *limiter) fail(key string, now time.Time) (lockedNow, globalNow bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.get(key, now)
	st.fails = append(prune(st.fails, now.Add(-lockoutWindow)), now)
	if len(st.fails) >= lockoutFailures && !now.Before(st.lockedUntil) {
		st.lockedUntil = now.Add(lockoutDuration)
		st.fails = nil
		lockedNow = true
	}
	l.globalFails = append(prune(l.globalFails, now.Add(-globalFailWindow)), now)
	if len(l.globalFails) > globalFailLimit && !now.Before(l.globalUntil) {
		l.globalUntil = now.Add(globalThrottleFor)
		globalNow = true
	}
	return lockedNow, globalNow
}

// globalAllow applies the server-wide auth throttle while it is engaged.
func (l *limiter) globalAllow(now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.globalUntil) {
		return true, 0
	}
	return reserve(l.global, now)
}

// failures returns the number of recent failures recorded for key (tests).
func (l *limiter) failures(key string, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.ips[key]
	if !ok {
		return 0
	}
	return len(prune(st.fails, now.Add(-lockoutWindow)))
}

func (l *limiter) cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(now)
}

func (l *limiter) cleanupLocked(now time.Time) {
	for k, st := range l.ips {
		if now.Sub(st.lastSeen) > limiterIdleExpiry && !now.Before(st.lockedUntil) {
			delete(l.ips, k)
		}
	}
	l.globalFails = prune(l.globalFails, now.Add(-globalFailWindow))
}

func prune(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return append(ts[:0:0], ts[i:]...)
}
