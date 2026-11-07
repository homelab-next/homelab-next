// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strconv"
)

// HeaderAttemptedFallbacks says how many fallback roles were tried when one of them served.
const HeaderAttemptedFallbacks = "X-HNX-Attempted-Fallbacks"

// statusClientGone is recorded when the caller hung up before any deployment answered.
const statusClientGone = 499

// route tries the role's deployments in order, then each fallback role that TLP and its own
// limit admit (a refused fallback is skipped), and answers 502 when every one failed with a
// fallback-eligible error or was skipped (R3, R6).
func (s *Server) route(w http.ResponseWriter, r *http.Request, cl *call) {
	credsRefused := false
	if s.tryRole(w, r, cl, cl.role, &credsRefused) {
		return
	}
	for _, name := range cl.role.Fallbacks {
		if r.Context().Err() != nil {
			break
		}
		fr := s.cfg.Roles[name]
		if !s.tlpAdmit(cl, fr).Allowed {
			s.log.Info("fallback skipped: tlp", "request_id", cl.id, "role", name)
			continue
		}
		if !s.limits.AdmitRole(cl.res, name, s.estimate(cl, fr)) {
			s.log.Info("fallback skipped: role limit", "request_id", cl.id, "role", name)
			continue
		}
		cl.fallbacks++
		if s.tryRole(w, r, cl, fr, &credsRefused) {
			return
		}
	}
	if r.Context().Err() != nil {
		cl.status = statusClientGone
		return
	}
	e := upstreamExhausted(credsRefused)
	if !cl.called && cl.unsupported != nil {
		// no deployment could take the request: that is the caller's error, not the upstream's
		e = cl.unsupported
	}
	cl.status, cl.errorCode = e.status, e.code
	e.write(w)
}

// markServed sets HeaderAttemptedFallbacks on a success answered by a fallback role; called just
// before a 2xx reply is written (an error answered on a fallback's behalf carries none).
func (cl *call) markServed(w http.ResponseWriter) {
	if cl.fallbacks > 0 {
		w.Header().Set(HeaderAttemptedFallbacks, strconv.Itoa(cl.fallbacks))
	}
}

// tryRole tries each deployment of role in order; true once one answered the caller.
// credsRefused is set when an upstream answered 401 or 403 (R6).
func (s *Server) tryRole(w http.ResponseWriter, r *http.Request, cl *call, role *Role, credsRefused *bool) bool {
	for _, d := range role.Deployments {
		if r.Context().Err() != nil {
			return false
		}
		res := s.attempt(w, r, cl, d)
		if res.upstreamOK && (!res.answered || res.code == errOverloaded.code) {
			// the reply was discarded: charge the attempt what it reserved (settled in record)
			cl.discarded = append(cl.discarded, spent{role: role.alias, tokens: s.estimate(cl, role)})
		}
		if res.answered {
			cl.status, cl.errorCode, cl.servedRole, cl.deployment = res.status, res.code, role.alias, d.ID
			cl.usage, cl.ttft = res.usage, res.ttft
			return true
		}
		if res.unsupported != nil && cl.unsupported == nil {
			cl.unsupported = res.unsupported
		}
		if res.credsRefused {
			*credsRefused = true
		}
		s.log.Warn("deployment failed, trying the next", "request_id", cl.id,
			"deployment", d.ID, "reason", res.reason)
	}
	return false
}
