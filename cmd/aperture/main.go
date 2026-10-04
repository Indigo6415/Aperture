// Command aperture starts the Aperture web UI: a local recon
// orchestration tool that wraps ffuf/feroxbuster and lets you chain their
// output together in a node-based flow editor.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Indigo6415/Aperture/internal/api"
	"github.com/Indigo6415/Aperture/internal/collaborator"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/webui"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// defaultUserEmail is the login seeded on a fresh install (see
// EnsureDefaultUser). Its password is random, generated on first run, and
// printed once to the log, so no install ships with a guessable credential.
const defaultUserEmail = "user"

// generatePassword returns a random 24-character password drawn from
// crypto/rand, for the first-run account.
func generatePassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8337", "address to listen on")
	collabAddr := flag.String("collab-addr", "0.0.0.0:8338", "address for the callback-only listener targets call back to (LAN/public); empty disables it")
	dbPath := flag.String("db", defaultDBPath(), "path to the SQLite database file")
	open := flag.Bool("open", true, "open the UI in your default browser on start")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("aperture: %v", err)
	}
	defer st.Close()

	// Seeds a single test login on first run only -- see EnsureDefaultUser,
	// which no-ops once any account exists so this never recreates a login
	// someone has since changed or deleted.
	firstPassword, err := generatePassword()
	if err != nil {
		log.Fatalf("aperture: generate password: %v", err)
	}
	created, err := st.EnsureDefaultUser(defaultUserEmail, firstPassword)
	if err != nil {
		log.Fatalf("aperture: %v", err)
	}
	if created {
		log.Printf("aperture: created first login %q with password %q -- shown only once, change it after signing in", defaultUserEmail, firstPassword)
	}

	wordlistsDir := defaultWordlistsDir()
	if err := wordlists.EnsureDefault(wordlistsDir); err != nil {
		log.Fatalf("aperture: %v", err)
	}

	eng := engine.New()
	srv := api.NewServer(st, eng, webui.FS(), wordlistsDir)
	srv.SetGitDumpDir(defaultGitDumpDir())

	httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler()}

	// Separate callback-only listener, so the UI stays on -addr (localhost by
	// default) while outside hosts can still reach /collab/... on -collab-addr.
	// The callback listener serves HTTP and HTTPS on one port (see
	// collaborator.Serve); both servers share the same handler.
	var collabPlain, collabSecure *http.Server
	if *collabAddr != "" {
		// Refuse a collab port that equals the UI port: the two listeners
		// would race for one socket, and the UI must stay off the public side.
		if uiPort, collabPort := portOf(*addr), portOf(*collabAddr); uiPort != "" && uiPort == collabPort {
			log.Fatalf("aperture: -collab-addr (%s) must use a different port than -addr (%s)", *collabAddr, *addr)
		}
		collabPlain = &http.Server{Handler: srv.CallbackHandler()}
		collabSecure = &http.Server{Handler: srv.CallbackHandler(), TLSConfig: srv.CallbackTLSConfig()}
		srv.SetCollabListenAddr(*collabAddr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("aperture: listening on http://%s (db: %s)", *addr, *dbPath)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("aperture: %v", err)
		}
	}()

	if collabPlain != nil {
		ln, err := net.Listen("tcp", *collabAddr)
		if err != nil {
			log.Fatalf("aperture: collaborator listener: %v", err)
		}
		go func() {
			log.Printf("aperture: collaborator callbacks on http(s)://%s/collab/", *collabAddr)
			if err := collaborator.Serve(ln, collabPlain, collabSecure, srv.CallbackTLSEnabled); err != nil && err != http.ErrServerClosed {
				log.Fatalf("aperture: collaborator listener: %v", err)
			}
		}()
	}

	if *open {
		go openBrowser("http://" + *addr)
	}

	<-ctx.Done()
	log.Println("aperture: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	if collabPlain != nil {
		_ = collabPlain.Shutdown(shutdownCtx)
		_ = collabSecure.Shutdown(shutdownCtx)
	}
}

// portOf returns the port part of a host:port listen address, or "" if it
// can't be parsed. Used to detect when the UI and collaborator listeners were
// given the same port.
func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

func defaultDBPath() string {
	apDir, ok := apertureDir()
	if !ok {
		return "aperture.db"
	}
	return filepath.Join(apDir, "aperture.db")
}

// defaultWordlistsDir returns where downloaded/bundled fuzzing wordlists
// are stored, falling back to a relative dir next to the binary under the
// same conditions defaultDBPath does.
func defaultWordlistsDir() string {
	apDir, ok := apertureDir()
	if !ok {
		return "wordlists"
	}
	return filepath.Join(apDir, "wordlists")
}

// defaultGitDumpDir returns where git dump buckets are written and served
// from. It sits next to the wordlists, and falls back to a relative dir under
// the same conditions defaultWordlistsDir does.
func defaultGitDumpDir() string {
	apDir, ok := apertureDir()
	if !ok {
		return "gitdumps"
	}
	return filepath.Join(apDir, "gitdumps")
}

// apertureDir returns (and creates) the per-user directory Aperture keeps
// its own state in -- the SQLite DB and downloaded wordlists both live
// under it. The bool is false if the OS's config dir couldn't be
// determined or created, so callers can fall back to a relative path.
func apertureDir() (string, bool) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", false
	}
	apDir := filepath.Join(dir, "aperture")
	if err := os.MkdirAll(apDir, 0o755); err != nil {
		return "", false
	}
	return apDir, true
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
