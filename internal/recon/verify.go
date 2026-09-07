package recon

import (
	"context"
	"net"
	"sync"
)

// secondaryDNSServer is an independent resolver used alongside the OS's
// default one in verifySubdomains -- deliberately not the same resolver
// checkDNS uses, so a candidate only counts as verified if two genuinely
// different resolution paths agree it's alive. Catches stale
// crt.sh/DNSDumpster entries that no longer resolve anywhere, or that only
// "resolve" via a stale local cache.
const secondaryDNSServer = "1.1.1.1:53"

// secondaryResolver bypasses the OS resolver entirely (PreferGo forces Go's
// own DNS client instead of cgo/system calls) and talks to
// secondaryDNSServer directly.
var secondaryResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: subdomainTimeout}
		return d.DialContext(ctx, network, secondaryDNSServer)
	},
}

// verifySubdomains filters candidates down to the ones that resolve via two
// independent paths: the system's default resolver and secondaryResolver
// above. A name that resolves via only one (a hijacked/stale local cache,
// or a resolver-specific outage) is dropped rather than treated as live.
// Order of candidates is preserved; concurrency is bounded the same way
// fanOutSubdomains bounds its own per-subdomain checks.
func verifySubdomains(ctx context.Context, candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}

	verified := make([]bool, len(candidates))
	sem := make(chan struct{}, subdomainWorkers)
	var wg sync.WaitGroup
	for i, name := range candidates {
		i, name := i, name
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			verified[i] = verifyOnce(ctx, name)
		}()
	}
	wg.Wait()

	out := make([]string, 0, len(candidates))
	for i, name := range candidates {
		if verified[i] {
			out = append(out, name)
		}
	}
	return out
}

// verifyOnce reports whether name resolves via both the system resolver and
// secondaryResolver. The system-resolver lookup gets one retry on
// failure -- consistent with the retry-on-failure approach used for crt.sh
// -- since a single transient failure there shouldn't be enough to write a
// candidate off as dead.
func verifyOnce(ctx context.Context, name string) bool {
	cctx, cancel := context.WithTimeout(ctx, subdomainTimeout)
	defer cancel()
	if !resolves(cctx, net.DefaultResolver, name) {
		cctx2, cancel2 := context.WithTimeout(ctx, subdomainTimeout)
		defer cancel2()
		if !resolves(cctx2, net.DefaultResolver, name) {
			return false
		}
	}

	sctx, cancel := context.WithTimeout(ctx, subdomainTimeout)
	defer cancel()
	return resolves(sctx, secondaryResolver, name)
}

func resolves(ctx context.Context, resolver *net.Resolver, name string) bool {
	_, err := resolver.LookupHost(ctx, name)
	return err == nil
}
