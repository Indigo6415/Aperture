package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Indigo6415/Aperture/internal/store"
)

// sessionCookie is the name of the cookie a successful login sets and
// requireAuth reads back on every subsequent request.
const sessionCookie = "aperture_session"

// sessionTTL is how long a login session stays valid without needing to
// sign in again -- generous since Aperture is a single-operator tool
// running on the operator's own machine, not a shared multi-tenant service
// where a long-lived session is a bigger risk.
const sessionTTL = 30 * 24 * time.Hour

// userContextKey is the context.Context key requireAuth stashes the
// authenticated user under, for handlers (currently just handleMe) that
// need to know who's asking.
type userContextKey struct{}

func newSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// requireAuth wraps next so it only runs once a valid session cookie is
// presented; otherwise it responds 401 without calling next at all. Used to
// gate every /api and /ws route except the login endpoint itself -- see
// withAuth in server.go, which decides what needs this wrapper in the
// first place.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("not signed in"))
			return
		}
		user, err := s.store.GetSessionUser(cookie.Value)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, errors.New("session expired or invalid"))
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey{}, user)
		next(w, r.WithContext(ctx))
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Email string `json:"email"`
}

// handleLogin verifies email+password against store.VerifyPassword and, on
// success, mints a new session token and sets it as an HttpOnly cookie.
// Wrong email and wrong password get the identical error message/status --
// see VerifyPassword's doc comment on why the two must not be
// distinguishable to the caller.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("email and password are required"))
		return
	}

	user, ok, err := s.store.VerifyPassword(req.Email, req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("invalid email or password"))
		return
	}

	token := newSessionToken()
	expiresAt := time.Now().Add(sessionTTL)
	if err := s.store.CreateSession(token, user.ID, expiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Aperture listens on plain HTTP on loopback by default (see
		// cmd/aperture/main.go's -addr flag) -- requiring Secure here would
		// make the cookie never round-trip and lock every operator out.
		Secure: r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, loginResponse{Email: user.Email})
}

// handleLogout deletes the session server-side (so the token can't be
// replayed even if a copy of the cookie leaked) and clears it client-side.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// handleMe reports who's currently signed in -- the frontend calls this
// once on load to decide whether to show the login screen or the app
// itself, since a plain 401 from any other endpoint is ambiguous between
// "never logged in" and "session just expired."
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := r.Context().Value(userContextKey{}).(store.User)
	writeJSON(w, http.StatusOK, loginResponse{Email: user.Email})
}
