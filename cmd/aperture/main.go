// Command aperture starts the Aperture web UI: a local recon
// orchestration tool that wraps ffuf/feroxbuster and lets you chain their
// output together in a node-based flow editor.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/Indigo6415/Aperture/internal/api"
	"github.com/Indigo6415/Aperture/internal/engine"
	"github.com/Indigo6415/Aperture/internal/store"
	"github.com/Indigo6415/Aperture/internal/webui"
	"github.com/Indigo6415/Aperture/internal/wordlists"
)

// defaultUserEmail/defaultUserPassword seed a single test login on a fresh
// install (see EnsureDefaultUser) so there's always something to sign in
// with out of the box -- change or delete it via a later "manage users"
// feature once one exists; for now it's the only account creation path.
const (
	defaultUserEmail    = "user"
	defaultUserPassword = "user"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8337", "address to listen on")
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
	if err := st.EnsureDefaultUser(defaultUserEmail, defaultUserPassword); err != nil {
		log.Fatalf("aperture: %v", err)
	}

	wordlistsDir := defaultWordlistsDir()
	if err := wordlists.EnsureDefault(wordlistsDir); err != nil {
		log.Fatalf("aperture: %v", err)
	}

	eng := engine.New()
	srv := api.NewServer(st, eng, webui.FS(), wordlistsDir)

	httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler()}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("aperture: listening on http://%s (db: %s)", *addr, *dbPath)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("aperture: %v", err)
		}
	}()

	if *open {
		go openBrowser("http://" + *addr)
	}

	<-ctx.Done()
	log.Println("aperture: shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
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
