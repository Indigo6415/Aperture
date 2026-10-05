package api

import (
	"net"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
)

// upgrader accepts only same-origin upgrades, or ones from a loopback origin.
// The loopback case keeps the Vite dev server (a different port than the
// backend, proxying /ws through) working. Rejecting every other origin stops a
// page on some other site from opening a socket that rides on the operator's
// session cookie (cross-site WebSocket hijacking). Access is still gated by
// requireAuth in server.go, so this is defense in depth.
var upgrader = websocket.Upgrader{
	CheckOrigin: originAllowed,
}

// originAllowed reports whether a request's Origin header is allowed.
// A request with no Origin (a non-browser client such as curl) is allowed,
// since cookies still have to match. Otherwise the origin must name the same
// host as the request or a loopback address.
func originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleWatchJob streams RunEvents for one job (whatever its tool) to a
// WebSocket client in real time. Events that arrived before the client
// connected are not replayed here; the client fetches those via REST --
// GET /api/jobs/{id} plus, for an engine-backed job, GET /api/runs/{runId}/
// findings, or GET /api/cases/{id}/checks for an identify job.
func (s *Server) handleWatchJob(w http.ResponseWriter, r *http.Request) {
	s.watch(w, r, r.PathValue("id"))
}

// watch is the subscribe-and-relay loop behind handleWatchJob: the hub is
// keyed by an arbitrary string ID (a jobID).
func (s *Server) watch(w http.ResponseWriter, r *http.Request, id string) {
	s.watchWithStart(w, r, id, nil)
}

// handleWatchEvents streams the global events channel (network-governor
// state changes -- see the netgov hook in NewServer) to a client for the
// whole session, rather than for one job. The frontend keeps a single such
// socket open so notification rules can alert on throttling/drift the moment
// it happens, whichever scan triggered it.
func (s *Server) handleWatchEvents(w http.ResponseWriter, r *http.Request) {
	s.watch(w, r, globalEventsKey)
}

// watchWithStart is watch, plus an optional start callback invoked right
// after subscribing to id's hub channel and before relaying begins --
// handleWatchProbeScan uses this to only start a probe scan once a client
// is actually subscribed to hear about it, since a scan can otherwise
// finish (and every event with it) before the WebSocket handshake that
// would have received them completes.
func (s *Server) watchWithStart(w http.ResponseWriter, r *http.Request, id string, start func()) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	events := s.hub.subscribe(id)
	defer s.hub.unsubscribe(id, events)

	if start != nil {
		start()
	}

	// The only messages we expect from the client are close frames; this
	// goroutine's sole purpose is to notice the connection went away.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := conn.WriteJSON(ev); err != nil {
				return
			}
		case <-closed:
			return
		}
	}
}
