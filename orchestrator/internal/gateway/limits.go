// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sort"
	"sync"
	"time"
)

// maxRetryWalk bounds how many buckets a refusal walks to compute Retry-After; past it the
// gateway answers with the time the walked buckets need to expire (a retry then may be refused
// again, with a later Retry-After).
const maxRetryWalk = 64

// bucket is one second of a window: what was admitted (requests, reservations) and spent in it.
type bucket struct {
	sec      int64
	requests int
	tokens   float64
	cost     float64
}

// budget is one sliding window kept as running sums over per-second buckets: Admit and Settle do
// bounded work whatever the request rate (at most one bucket per second of the window is kept,
// and each bucket is dropped once). An event leaves the window window_s seconds after the start
// of its second. A dimension with a nil max keeps nothing: requests are counted only when
// max_requests is set, tokens only when max_tokens is, cost only when max_cost is.
type budget struct {
	window      int64 // seconds
	maxRequests *int
	maxTokens   *int
	maxCost     *float64

	buckets  []bucket // oldest first, strictly increasing sec
	requests int
	tokens   float64
	cost     float64
}

func newBudget(windowS int, maxRequests, maxTokens *int, maxCost *float64) *budget {
	return &budget{window: int64(windowS), maxRequests: maxRequests, maxTokens: maxTokens, maxCost: maxCost}
}

// prune drops every bucket whose second started at or before now-window.
func (b *budget) prune(now time.Time) {
	cut := now.Unix() - b.window
	i := 0
	for i < len(b.buckets) && b.buckets[i].sec <= cut {
		e := b.buckets[i]
		b.requests -= e.requests
		b.tokens -= e.tokens
		b.cost -= e.cost
		i++
	}
	b.buckets = b.buckets[i:]
	if len(b.buckets) == 0 {
		b.requests, b.tokens, b.cost = 0, 0, 0 // no float drift survives an empty window
	}
}

// current is the bucket of now's second, created when missing (a clock that went back adds to
// the newest bucket).
func (b *budget) current(now time.Time) *bucket {
	sec := now.Unix()
	if n := len(b.buckets); n > 0 && b.buckets[n-1].sec >= sec {
		return &b.buckets[n-1]
	}
	b.buckets = append(b.buckets, bucket{sec: sec})
	return &b.buckets[len(b.buckets)-1]
}

func (b *budget) find(sec int64) *bucket {
	i := sort.Search(len(b.buckets), func(i int) bool { return b.buckets[i].sec >= sec })
	if i < len(b.buckets) && b.buckets[i].sec == sec {
		return &b.buckets[i]
	}
	return nil
}

// fits says whether the window, holding requests, tokens and cost, has room for one more request
// that reserves tokens and cost. A window refuses once a sum reaches its max, and refuses a
// reservation that would take a sum past its max.
func (b *budget) fits(requests int, tokens, cost, addTokens, addCost float64) bool {
	if b.maxRequests != nil && requests >= *b.maxRequests {
		return false
	}
	if b.maxTokens != nil {
		max := float64(*b.maxTokens)
		if tokens >= max || tokens+addTokens > max {
			return false
		}
	}
	if b.maxCost != nil && (cost >= *b.maxCost || cost+addCost > *b.maxCost) {
		return false
	}
	return true
}

// refusal says whether one more request reserving tokens and cost is refused, and when to retry.
func (b *budget) refusal(now time.Time, addTokens, addCost float64) (time.Duration, bool) {
	b.prune(now)
	if b.fits(b.requests, b.tokens, b.cost, addTokens, addCost) {
		return 0, false
	}
	req, tok, cost := b.requests, b.tokens, b.cost
	for i, e := range b.buckets {
		if i == maxRetryWalk {
			return time.Unix(b.buckets[i-1].sec+b.window, 0).Sub(now), true
		}
		req, tok, cost = req-e.requests, tok-e.tokens, cost-e.cost
		if b.fits(req, tok, cost, addTokens, addCost) {
			return time.Unix(e.sec+b.window, 0).Sub(now), true
		}
	}
	// the reservation alone is over a max: no amount of waiting admits it
	return time.Duration(b.window) * time.Second, true
}

// Limiter holds every key's and role's window, in memory (a restart starts every window again).
type Limiter struct {
	mu    sync.Mutex
	now   func() time.Time
	keys  map[string]*budget
	roles map[string]*budget
	cost  map[string]float64 // role -> cost per 1k tokens
}

// NewLimiter builds the windows the config declares.
func NewLimiter(c *Config, now func() time.Time) *Limiter {
	l := &Limiter{now: now, keys: map[string]*budget{}, roles: map[string]*budget{}, cost: map[string]float64{}}
	for alias, r := range c.Roles {
		if r.CostPer1KTokens != nil {
			l.cost[alias] = *r.CostPer1KTokens
		}
		if r.Limits != nil {
			l.roles[alias] = newBudget(r.Limits.WindowS, r.Limits.MaxRequests, r.Limits.MaxTokens, r.Limits.MaxCost)
		}
	}
	for _, k := range c.Keys {
		if k.Limits != nil {
			l.keys[k.Alias] = newBudget(k.Limits.WindowS, k.Limits.MaxRequests, k.Limits.MaxTokens, nil)
		}
	}
	return l
}

// exceeds names the limit ("token" or "cost") that a reservation alone is larger than, so that
// no amount of waiting admits it; "" when it fits an empty window.
func (b *budget) exceeds(tokens, cost float64) string {
	if b == nil {
		return ""
	}
	if b.maxTokens != nil && tokens > float64(*b.maxTokens) {
		return "token"
	}
	if b.maxCost != nil && cost > *b.maxCost {
		return "cost"
	}
	return ""
}

// Exceeds says whether a reservation of tokens is larger than the key's or the role's token or
// cost max by itself: such a call can never be admitted. It returns the scope ("key" or "role")
// and the limit ("token" or "cost"), the key first.
func (l *Limiter) Exceeds(key, role string, tokens int) (scope, limit string, over bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := float64(tokens)
	if lim := l.keys[key].exceeds(t, 0); lim != "" {
		return "key", lim, true
	}
	if lim := l.roles[role].exceeds(t, t/1000*l.cost[role]); lim != "" {
		return "role", lim, true
	}
	return "", "", false
}

// Reservation is what an admitted call holds on its windows until it is settled: its estimate of
// tokens (and, on a role with a cost, of cost), in the bucket of the second it was admitted.
type Reservation struct {
	holds []hold
}

type hold struct {
	b      *budget
	sec    int64
	tokens float64
	cost   float64
}

// add counts one request and reserves tokens (and cost) on b in now's bucket.
func (r *Reservation) add(b *budget, now time.Time, tokens, cost float64) {
	e := b.current(now)
	if b.maxRequests != nil {
		e.requests++
		b.requests++
	}
	h := hold{b: b, sec: e.sec}
	if b.maxTokens != nil {
		h.tokens = tokens
	}
	if b.maxCost != nil {
		h.cost = cost
	}
	e.tokens += h.tokens
	e.cost += h.cost
	b.tokens += h.tokens
	b.cost += h.cost
	if h.tokens != 0 || h.cost != 0 {
		r.holds = append(r.holds, h)
	}
}

// Admit checks the key's window, then the role's, for one more request reserving tokens (and the
// role's cost of them), and counts the request and holds the reservation on both only when
// neither refuses: a 429 consumes nothing. key "" (the admin key) has no window. It returns the
// reservation to settle, or the scope that refused ("key" or "role") and the retry delay.
func (l *Limiter) Admit(key, role string, tokens int) (*Reservation, string, time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	t := float64(tokens)
	c := t / 1000 * l.cost[role]
	kb, rb := l.keys[key], l.roles[role]
	if kb != nil {
		if d, refused := kb.refusal(now, t, 0); refused {
			return nil, "key", d, false
		}
	}
	if rb != nil {
		if d, refused := rb.refusal(now, t, c); refused {
			return nil, "role", d, false
		}
	}
	res := &Reservation{}
	if kb != nil {
		res.add(kb, now, t, 0)
	}
	if rb != nil {
		res.add(rb, now, t, c)
	}
	return res, "", 0, true
}

// AdmitRole checks and counts one request reserving tokens on a fallback role's own window, and
// adds the hold to res.
func (l *Limiter) AdmitRole(res *Reservation, role string, tokens int) bool {
	r, _, _, ok := l.Admit("", role, tokens)
	if ok && res != nil {
		res.holds = append(res.holds, r.holds...)
	}
	return ok
}

// Settle releases every hold of res (a hold whose bucket already left the window has nothing to
// release) and spends the call's real tokens on the key and on the role that served it, and their
// cost on that role. role "" spends nothing (no deployment served).
func (l *Limiter) Settle(res *Reservation, key, role string, tokens int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if res != nil {
		for _, h := range res.holds {
			if e := h.b.find(h.sec); e != nil {
				e.tokens -= h.tokens
				e.cost -= h.cost
				h.b.tokens -= h.tokens
				h.b.cost -= h.cost
			}
		}
		res.holds = nil
	}
	l.spend(key, role, tokens)
}

// Spend counts tokens on the key and on role (and their cost on role) with no reservation to
// release: what a call whose reply was discarded is charged for the attempt.
func (l *Limiter) Spend(key, role string, tokens int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.spend(key, role, tokens)
}

func (l *Limiter) spend(key, role string, tokens int) {
	if role == "" || tokens <= 0 {
		return
	}
	now := l.now()
	t := float64(tokens)
	spend := func(b *budget, cost float64) {
		b.prune(now)
		if b.maxTokens == nil && b.maxCost == nil {
			return
		}
		e := b.current(now)
		if b.maxTokens != nil {
			e.tokens += t
			b.tokens += t
		}
		if b.maxCost != nil {
			e.cost += cost
			b.cost += cost
		}
	}
	if kb := l.keys[key]; kb != nil {
		spend(kb, 0)
	}
	if rb := l.roles[role]; rb != nil {
		spend(rb, t/1000*l.cost[role])
	}
}
