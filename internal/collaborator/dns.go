package collaborator

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// dnsMaxMessage is the UDP read buffer size -- plenty for the tiny,
// single-question queries a Collaborator-style probe sends; a real resolver
// would fall back to TCP for anything larger, which this listener doesn't
// implement (no legitimate caller needs it here).
const dnsMaxMessage = 512

// dnsTypeNames covers the record types a blind-SSRF/OOB payload actually
// triggers in practice (a resolver library resolving a hostname almost
// always starts with A, sometimes AAAA; the rest are here mainly so an
// interaction's queryType reads as something recognizable rather than a bare
// number).
var dnsTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
}

func dnsTypeName(t uint16) string {
	if name, ok := dnsTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// StartDNS starts a minimal authoritative DNS server on addr: any query for
// a name ending in domain gets answered (A queries get answerIP back;
// anything else gets an empty, still-NOERROR answer, since the query itself
// -- not the answer -- is the signal this exists to catch) and logged as a
// DNS Interaction against whichever token forms the label immediately
// preceding domain (see extractTokenAndIdentifier). This is what lets a *blind* SSRF/XXE/
// etc. payload be caught even when the target's egress firewall blocks the
// outbound TCP connection a full HTTP callback would need -- the DNS lookup
// that precedes it often still leaks out.
//
// domain should be the operator's own domain (or subdomain) with its NS
// records pointed at wherever this process is reachable from the internet --
// see the package doc comment for why this works without that domain
// configured too (the HTTP listener alone still catches non-blind cases).
// answerIP is normally the same host's own public IP, so a payload that does
// complete its connection lands on this same process's HTTP listener.
//
// The returned stop func closes the listener; err is non-nil only if the
// bind itself failed (wrong address, port already in use, or -- for a port
// below 1024 -- this process lacking the privilege to bind it).
func (r *Registry) StartDNS(addr, domain, answerIP string) (stop func(), err error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("collaborator: DNS listen on %q failed: %w", addr, err)
	}

	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	var ipv4 [4]byte
	haveV4 := false
	if ip := net.ParseIP(answerIP); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			copy(ipv4[:], v4)
			haveV4 = true
		}
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, dnsMaxMessage)
		for {
			select {
			case <-done:
				return
			default:
			}
			// A short read deadline lets this loop notice `done` being
			// closed promptly instead of blocking forever on a listener
			// that may never receive another packet.
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, raddr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
					continue
				}
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			msg := make([]byte, n)
			copy(msg, buf[:n])
			go r.handleDNSQuery(conn, raddr, msg, domain, ipv4, haveV4)
		}
	}()

	return func() {
		close(done)
		_ = conn.Close()
	}, nil
}

// handleDNSQuery parses one query, records an Interaction against its
// target token (if its name matches domain), and always answers -- even a
// query for an unrecognized token gets a normal-looking response, same as a
// real Collaborator server, so a resolver retrying/giving up doesn't itself
// tip off whoever's watching that this listener is selective.
func (r *Registry) handleDNSQuery(conn net.PacketConn, raddr net.Addr, msg []byte, domain string, ipv4 [4]byte, haveV4 bool) {
	id, name, qtype, qEnd, ok := parseDNSQuestion(msg)
	if !ok {
		return
	}

	lname := strings.ToLower(strings.TrimSuffix(name, "."))
	if token, identifier := extractTokenAndIdentifier(lname, domain); token != "" {
		r.Record(token, Interaction{
			ID:         randomHex(4),
			Protocol:   "dns",
			Timestamp:  time.Now(),
			RemoteAddr: raddr.String(),
			QueryName:  lname,
			QueryType:  dnsTypeName(qtype),
			Identifier: identifier,
		})
	}

	resp := buildDNSResponse(msg, qEnd, id, qtype, ipv4, haveV4)
	_, _ = conn.WriteTo(resp, raddr)
}

// extractTokenAndIdentifier splits name into its token label (the one
// immediately preceding domain) and, when present, an identifier made of
// every label still further out -- e.g.
// name="ssrf-webhook_url.deadbeef0123.collab.example.com",
// domain="collab.example.com" returns token="deadbeef0123",
// identifier="ssrf-webhook_url". A bare "<token>.collab.example.com" query
// (no identifier, e.g. a manual payload copied from the Collaborator tab)
// returns identifier="". Returns token="" when name doesn't actually end in
// domain at all (a stray query for something unrelated landing on this
// listener) or has no label before it.
func extractTokenAndIdentifier(name, domain string) (token, identifier string) {
	if domain == "" {
		return "", ""
	}
	var prefix string
	switch {
	case name == domain:
		return "", ""
	case strings.HasSuffix(name, "."+domain):
		prefix = strings.TrimSuffix(name, "."+domain)
	default:
		return "", ""
	}
	if prefix == "" {
		return "", ""
	}
	labels := strings.Split(prefix, ".")
	token = labels[len(labels)-1]
	if len(labels) > 1 {
		identifier = strings.Join(labels[:len(labels)-1], ".")
	}
	return token, identifier
}

// parseDNSQuestion reads a DNS message's header ID and its first question
// (name/qtype) -- the only two things this listener ever needs, since every
// query it receives is expected to carry exactly one question, the normal
// shape a stub resolver sends. qEnd is the byte offset immediately after the
// question section, so the caller can echo it verbatim into the response
// (simplest possible spec-compliant reply: the question section round-trips
// unchanged).
func parseDNSQuestion(msg []byte) (id uint16, name string, qtype uint16, qEnd int, ok bool) {
	if len(msg) < 12 {
		return 0, "", 0, 0, false
	}
	id = binary.BigEndian.Uint16(msg[0:2])
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	if qdcount == 0 {
		return 0, "", 0, 0, false
	}

	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return 0, "", 0, 0, false
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		// A compressed name (0xC0 top bits) is illegal in the question
		// section of a well-formed query -- bail rather than try to
		// resolve it, since no legitimate stub resolver sends one here.
		if l&0xC0 == 0xC0 {
			return 0, "", 0, 0, false
		}
		off++
		if off+l > len(msg) {
			return 0, "", 0, 0, false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	if off+4 > len(msg) {
		return 0, "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[off : off+2])
	qEnd = off + 4 // +2 qtype, +2 qclass
	return id, strings.Join(labels, "."), qtype, qEnd, true
}

// buildDNSResponse builds a minimal, spec-compliant reply to a query whose
// question section is query[12:qEnd]: same ID and question echoed back, and
// -- only for an A query when a valid answerIP was configured -- one A
// record answer via a compression pointer back to the question's own name.
// Anything else (AAAA, MX, a query before answerIP is configured, ...) gets
// an empty NOERROR answer: still a valid, non-suspicious response, just with
// nothing behind it.
func buildDNSResponse(query []byte, qEnd int, id uint16, qtype uint16, ipv4 [4]byte, haveV4 bool) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	// QR=1 (response), Opcode=0 (query), AA=1 (authoritative for domain),
	// RCODE=0 (NOERROR).
	binary.BigEndian.PutUint16(header[2:4], 0x8400)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT

	answerThis := qtype == 1 && haveV4 // only A queries get an actual answer
	var ancount uint16
	if answerThis {
		ancount = 1
	}
	binary.BigEndian.PutUint16(header[6:8], ancount)
	binary.BigEndian.PutUint16(header[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], 0) // ARCOUNT

	out := make([]byte, 0, 12+(qEnd-12)+16)
	out = append(out, header...)
	out = append(out, query[12:qEnd]...) // question section, echoed verbatim

	if answerThis {
		out = append(out, 0xC0, 0x0C)             // name: compression pointer to offset 12
		out = append(out, 0x00, 0x01)             // TYPE A
		out = append(out, 0x00, 0x01)             // CLASS IN
		out = append(out, 0x00, 0x00, 0x00, 0x3C) // TTL 60s
		out = append(out, 0x00, 0x04)             // RDLENGTH 4
		out = append(out, ipv4[:]...)
	}
	return out
}
