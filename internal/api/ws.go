package api

import (
	"net/http"

	"github.com/gorilla/websocket"
)

// upgrader allows any origin: the frontend dev server runs on a different
// port than the backend, so a same-origin check would break local
// development. Access itself is still gated -- handleWatchJob sits behind
// requireAuth in server.go, same as every other /api and /ws route, so an
// upgrade request without a valid session cookie never reaches here.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
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
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	events := s.hub.subscribe(id)
	defer s.hub.unsubscribe(id, events)

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
