package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"dns_resolver/pkg/types/resolver_config"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

const testServerName = "upstream.test"

// answerFunc answers one query on behalf of the fake upstream. Returning nil
// sends nothing back, which the resolver sees as a query that timed out.
type answerFunc func(query *dns.Msg) *dns.Msg

// testUpstream is a DoT server on localhost standing in for the forwarder. It
// records every query it is sent and how many connections it accepted.
type testUpstream struct {
	address  string
	roots    *x509.CertPool
	accepted atomic.Int64

	mu      sync.Mutex
	queries []*dns.Msg
}

func (u *testUpstream) received() []*dns.Msg {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]*dns.Msg(nil), u.queries...)
}

// receivedFor counts the queries the upstream was sent for name.
func (u *testUpstream) receivedFor(name string) int {
	var count int
	for _, query := range u.received() {
		if len(query.Question) > 0 && strings.EqualFold(query.Question[0].Name, name) {
			count++
		}
	}
	return count
}

type countingListener struct {
	net.Listener
	accepted *atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return connection, err
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: testServerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{testServerName},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func startUpstream(t *testing.T, answer answerFunc) *testUpstream {
	t.Helper()

	certificate, roots := testCertificate(t)
	upstream := &testUpstream{roots: roots}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	upstream.address = listener.Addr().String()

	tlsListener := tls.NewListener(
		&countingListener{Listener: listener, accepted: &upstream.accepted},
		&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
	)

	started := make(chan struct{})
	server := &dns.Server{
		Listener:          tlsListener,
		Net:               "tcp-tls",
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, query *dns.Msg) {
			upstream.mu.Lock()
			upstream.queries = append(upstream.queries, query.Copy())
			upstream.mu.Unlock()

			if response := answer(query); response != nil {
				_ = writer.WriteMsg(response)
			}
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })

	return upstream
}

// answerWith returns an answerFunc giving every A query one address.
func answerWith(address string) answerFunc {
	return func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		question := query.Question[0]
		if question.Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP(address).To4(),
			}}
		}
		return response
	}
}

// answerRcode returns an answerFunc answering every query with rcode, and the
// SOA a negative answer is cached by.
func answerRcode(rcode int) answerFunc {
	return func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetRcode(query, rcode)
		response.Ns = []dns.RR{testSoa("example.")}
		return response
	}
}

func testSoa(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
}

func newTestResolver(t *testing.T, upstream *testUpstream, options ...resolver_config.Option) *Resolver {
	t.Helper()

	baseOptions := []resolver_config.Option{
		resolver_config.WithMaxConnections(4),
		resolver_config.WithMinIdleConnections(0),
		resolver_config.WithIdleTimeout(time.Minute),
		resolver_config.WithKeepAliveInterval(0),
	}
	resolver, err := New(t.Context(), "dot", upstream.address, testServerName, append(baseOptions, options...)...)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	resolver.DotConfig.Client.TLSConfig.RootCAs = upstream.roots
	t.Cleanup(func() { _ = resolver.Close() })

	return resolver
}

type testAddr struct{ network string }

func (a testAddr) Network() string { return a.network }
func (a testAddr) String() string  { return "192.0.2.7:5353" }

// testWriter captures what ServeDNS writes back to the client.
type testWriter struct {
	network string
	msgs    []*dns.Msg
}

func (w *testWriter) LocalAddr() net.Addr  { return testAddr{w.network} }
func (w *testWriter) RemoteAddr() net.Addr { return testAddr{w.network} }
func (w *testWriter) WriteMsg(m *dns.Msg) error {
	// What a client receives is the packed message; going through the wire
	// format also catches a reply that cannot be packed at all.
	packed, err := m.Pack()
	if err != nil {
		return err
	}
	received := new(dns.Msg)
	if err := received.Unpack(packed); err != nil {
		return err
	}
	w.msgs = append(w.msgs, received)
	return nil
}
func (w *testWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testWriter) Close() error              { return nil }
func (w *testWriter) TsigStatus() error         { return nil }
func (w *testWriter) TsigTimersOnly(bool)       {}
func (w *testWriter) Hijack()                   {}

func newQuery(name string, qtype uint16) *dns.Msg {
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	return query
}

// ask sends query to the resolver over network ("udp" or "tcp") and returns
// the reply, or nil when none was written.
func ask(r *Resolver, network string, query *dns.Msg) *dns.Msg {
	writer := &testWriter{network: network}
	r.ServeDNS(writer, query)
	if len(writer.msgs) == 0 {
		return nil
	}
	return writer.msgs[len(writer.msgs)-1]
}

func rcodeOf(m *dns.Msg) string {
	if m == nil {
		return "no reply"
	}
	return dns.RcodeToString[m.Rcode]
}
