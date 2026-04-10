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
	"strings"
	"sync/atomic"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
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
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("scanner err: %w", err))
	}

	return &Entries{v4: v4, v6: v6}, nil
}

// Load reads and parses the hosts file at path.
func Load(path string) (*Entries, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("os open: %w", err), path)
	}
	defer file.Close()

	entries, err := ParseReader(file)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("parse reader: %w", err), path)
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
// entries on success.
func (h *Hosts) Reload() error {
	if h == nil {
		return nil
	}
	entries, err := Load(h.path)
	if err != nil {
		return motmedelErrors.New(fmt.Errorf("load: %w", err), h.path)
	}
	h.entries.Store(entries)
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
// there is no matching entry (in which case the caller should fall through to
// the upstream resolver). Only A and AAAA queries in class IN are considered.
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
	default:
		return nil
	}

	if len(answers) == 0 {
		return nil
	}

	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.RecursionAvailable = true
	response.Answer = answers
	if opt := request.IsEdns0(); opt != nil {
		response.SetEdns0(opt.UDPSize(), false)
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
		return motmedelErrors.NewWithTrace(fmt.Errorf("filepath abs: %w", err), h.path)
	}
	dir := filepath.Dir(absPath)
	name := filepath.Base(absPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("fsnotify new watcher: %w", err))
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("fsnotify watcher add: %w", err), dir)
	}

	logReloadError := func(err error) {
		slog.ErrorContext(
			motmedelContext.WithError(
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
			if err := h.Reload(); err != nil {
				logReloadError(err)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.WarnContext(
				motmedelContext.WithError(
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
