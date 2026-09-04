package adapters

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// screenshotTimeout bounds one headless-Chrome capture -- generous enough
// for a slow site, short enough that a hung renderer can't stall the
// per-subdomain fan-out that triggers captures (see api.captureScreenshot).
const screenshotTimeout = 20 * time.Second

// chromeBinaries lists the executable names a headless-Chrome-compatible
// browser is commonly installed as, tried in order -- there's no single
// canonical name across Linux distros/macOS/Windows.
var chromeBinaries = []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge"}

// FindChromeBinary returns the first headless-Chrome-compatible binary found
// on PATH, or an error naming every name it tried if none is installed --
// exported so internal/report can reuse it for PDF rendering (also done via
// headless Chrome's --print-to-pdf) without duplicating this list.
func FindChromeBinary() (string, error) {
	for _, name := range chromeBinaries {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no headless-Chrome-compatible browser found on PATH (tried %v)", chromeBinaries)
}

// CaptureScreenshot renders targetURL headlessly and returns the resulting
// PNG bytes. This wraps whatever Chrome/Chromium binary is installed
// locally rather than a separate tool like gowitness, so Aperture doesn't
// gain an extra runtime dependency beyond a browser most systems already
// have for the vhost/content-discovery adapters' manual verification
// workflow anyway.
//
// Unlike the ffuf/feroxbuster/nmap/nuclei adapters, this isn't wired into
// engine.Registry as a flow source: a screenshot is one image per host, not
// a stream of model.Finding, so it's called directly (see
// api.captureScreenshot) rather than run as a flow node.
func CaptureScreenshot(ctx context.Context, targetURL string) ([]byte, error) {
	chrome, err := FindChromeBinary()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, screenshotTimeout)
	defer cancel()

	out, err := os.CreateTemp("", "aperture-screenshot-*.png")
	if err != nil {
		return nil, fmt.Errorf("screenshot: create temp file: %w", err)
	}
	outPath := out.Name()
	out.Close()
	defer os.Remove(outPath)

	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--hide-scrollbars",
		"--window-size=1280,800",
		"--screenshot=" + outPath,
		targetURL,
	}
	cmd := exec.CommandContext(ctx, chrome, args...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("screenshot: %s: %w", chrome, err)
	}

	image, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("screenshot: read output: %w", err)
	}
	if len(image) == 0 {
		return nil, fmt.Errorf("screenshot: %s produced an empty file", chrome)
	}
	return image, nil
}
