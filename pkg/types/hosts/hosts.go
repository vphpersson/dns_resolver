package hosts

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"

	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
)

// DefaultTtl is the TTL applied to synthesized answers when none is configured.
const DefaultTtl uint32 = 60

// Entries is an immutable snapshot of a parsed hosts file, keyed by
// lowercased FQDN (without a trailing dot).
type Entries struct {
	v4 map[string][]net.IP
	v6 map[string][]net.IP
}

// LookupA returns the IPv4 addresses mapped to name, or nil.
func (e *Entries) LookupA(name string) []net.IP {
	if e == nil {
		return nil
	}
	return e.v4[normalizeName(name)]
}

// LookupAAAA returns the IPv6 addresses mapped to name, or nil.
func (e *Entries) LookupAAAA(name string) []net.IP {
	if e == nil {
		return nil
	}
	return e.v6[normalizeName(name)]
}

// LoopbackNames returns, sorted, the names mapped to a loopback address that
// are not localhost. Because the hosts file is served to the whole network,
// such a name sends every client back to itself, and the symptom -- a host
// that answers DNS but is unreachable at the address it hands out -- reads as
// a network fault rather than a configuration one. The stock "127.0.1.1
// <hostname>" line does exactly this, so it is worth saying out loud.
func (e *Entries) LoopbackNames() []string {
	if e == nil {
		return nil
	}

	seen := make(map[string]struct{})
	for _, addresses := range []map[string][]net.IP{e.v4, e.v6} {
		for name, ips := range addresses {
			if isLocalhostName(name) {
				continue
			}
			for _, ip := range ips {
				if ip.IsLoopback() {
					seen[name] = struct{}{}
					break
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// isLocalhostName reports whether name is one the RFC 6761 special-use rules
// require to be a loopback address, and so is not worth warning about.
func isLocalhostName(name string) bool {
	return name == "localhost" ||
		name == "localhost.localdomain" ||
		strings.HasSuffix(name, ".localhost")
}

// Has reports whether name appears in the hosts file with an address of either
// family.
func (e *Entries) Has(name string) bool {
	if e == nil {
		return false
	}
	normalized := normalizeName(name)
	if _, ok := e.v4[normalized]; ok {
		return true
	}
	_, ok := e.v6[normalized]
	return ok
}

// normalizeName lowercases a DNS name and strips any trailing dot so it can
// be compared against the hostnames parsed out of a hosts file.
func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// ParseReader parses the content of a hosts file. Lines follow the format
//
//	IP  name  [alias...]
//
// with '#' introducing a comment. Blank lines and comment-only lines are
// ignored. Invalid lines are skipped.
func ParseReader(reader io.Reader) (*Entries, error) {
	if reader == nil {
		return &Entries{v4: map[string][]net.IP{}, v6: map[string][]net.IP{}}, nil
	}

	v4 := make(map[string][]net.IP)
	v6 := make(map[string][]net.IP)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil

		for _, raw := range fields[1:] {
			name := normalizeName(raw)
			if name == "" {
				continue
			}
			if isV4 {
				v4[name] = append(v4[name], ip.To4())
			} else {
				v6[name] = append(v6[name], ip)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("scanner err: %w", err))
	}

	return &Entries{v4: v4, v6: v6}, nil
}

// Load reads and parses the hosts file at path.
func Load(path string) (*Entries, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("os open: %w", err), path)
	}
	defer file.Close()

	entries, err := ParseReader(file)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("parse reader: %w", err), path)
	}
	return entries, nil
}

// Hosts is a live, reloadable view of a hosts file. It is safe for concurrent
// use; the entries pointer is swapped atomically.
type Hosts struct {
	path    string
	ttl     uint32
	entries atomic.Pointer[Entries]
}

// New creates a Hosts bound to path. If ttl is zero, DefaultTtl is used.
// The file is not read until Reload is called.
func New(path string, ttl uint32) *Hosts {
	if ttl == 0 {
		ttl = DefaultTtl
	}
	return &Hosts{path: path, ttl: ttl}
}

// Path returns the hosts file path the Hosts instance was configured with.
func (h *Hosts) Path() string {
	if h == nil {
		return ""
	}
	return h.path
}

// Reload reads and parses the hosts file and atomically swaps the active
// entries on success. Names that resolve to a loopback address are warned
// about but not withheld: what the file says is what gets served, and the
// point of the warning is that the file says something surprising.
func (h *Hosts) Reload(ctx context.Context) error {
	if h == nil {
		return nil
	}
	entries, err := Load(h.path)
	if err != nil {
		return altshiftErrors.New(fmt.Errorf("load: %w", err), h.path)
	}
	h.entries.Store(entries)

	if names := entries.LoopbackNames(); len(names) > 0 {
		slog.WarnContext(
			ctx,
			"",
			slog.Group(
				"event",
				slog.String("action", "hosts_reload"),
				slog.String("reason", "A name in the hosts file maps to a loopback address. It is served to the whole network, where it directs every client back to itself."),
				slog.String("kind", "event"),
				slog.String("outcome", "success"),
				slog.Any("category", []string{"file"}),
				slog.Any("type", []string{"info"}),
			),
			slog.Group("file", slog.String("path", h.path)),
			slog.Group("hosts", slog.Any("loopback_names", names)),
		)
	}

	return nil
}

// Entries returns the currently loaded entries, or nil if Reload has not yet
// succeeded.
func (h *Hosts) Entries() *Entries {
	if h == nil {
		return nil
	}
	return h.entries.Load()
}

// Resolve attempts to answer request from the hosts file. It returns nil when
// the name is absent from the file, in which case the caller should fall
// through to the upstream resolver. A name that is present is answered
// authoritatively whatever the type: with records for A and AAAA where the
// file holds them, and NODATA otherwise. Only class IN is considered.
func (h *Hosts) Resolve(request *dns.Msg) *dns.Msg {
	if h == nil || request == nil {
		return nil
	}
	if len(request.Question) == 0 {
		return nil
	}

	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return nil
	}

	entries := h.entries.Load()
	if entries == nil {
		return nil
	}

	// A name the hosts file knows is answered here for every type, including
	// the types it holds no record for. Falling through instead would forward
	// the query, and a name that exists only in this file comes back NXDOMAIN
	// -- which says the name does not exist at all, rather than that it has no
	// record of the type asked for. glibc resolves a hostname by asking for A
	// and AAAA together and fails the lookup outright on that NXDOMAIN, so an
	// IPv4-only entry would not resolve at all through getent, nss or anything
	// built on them, while a direct A query answered correctly.
	if !entries.Has(question.Name) {
		return nil
	}

	var answers []dns.RR
	switch question.Qtype {
	case dns.TypeA:
		for _, ip := range entries.LookupA(question.Name) {
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    h.ttl,
				},
				A: ip,
			})
		}
	case dns.TypeAAAA:
		for _, ip := range entries.LookupAAAA(question.Name) {
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    h.ttl,
				},
				AAAA: ip,
			})
		}
	}

	// An empty answer section is deliberate: NOERROR with no records is NODATA,
	// the correct way to say the name exists but holds nothing of this type.
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	response.Answer = answers
	if opt := request.IsEdns0(); opt != nil {
		response.SetEdns0(opt.UDPSize(), opt.Do())
	}
	return response
}

// Watch blocks until ctx is cancelled, reloading the hosts file whenever it
// changes. The parent directory is watched (rather than the file itself) so
// that editors that write atomically via rename are handled correctly, and
// reload errors are logged through slog instead of aborting the watch.
func (h *Hosts) Watch(ctx context.Context) error {
	if h == nil {
		return nil
	}

	absPath, err := filepath.Abs(h.path)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("filepath abs: %w", err), h.path)
	}
	dir := filepath.Dir(absPath)
	name := filepath.Base(absPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("fsnotify new watcher: %w", err))
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("fsnotify watcher add: %w", err), dir)
	}

	logReloadError := func(err error) {
		slog.ErrorContext(
			altshiftContext.WithError(
				ctx,
				fmt.Errorf("hosts reload: %w", err),
			),
			"",
			slog.Group(
				"event",
				slog.String("action", "hosts_reload"),
				slog.String("reason", "An error occurred when reloading the hosts file."),
				slog.String("kind", "event"),
				slog.String("outcome", "failure"),
				slog.Any("category", []string{"file"}),
				slog.Any("type", []string{"error"}),
			),
		)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if filepath.Base(event.Name) != name {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			if err := h.Reload(ctx); err != nil {
				logReloadError(err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.WarnContext(
				altshiftContext.WithError(
					ctx,
					fmt.Errorf("fsnotify watcher: %w", err),
				),
				"",
				slog.Group(
					"event",
					slog.String("action", "hosts_watch"),
					slog.String("reason", "A file watcher error occurred."),
					slog.String("kind", "event"),
					slog.String("outcome", "failure"),
					slog.Any("category", []string{"file"}),
					slog.Any("type", []string{"error"}),
				),
			)
		}
	}
}
