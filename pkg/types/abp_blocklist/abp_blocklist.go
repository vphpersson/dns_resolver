package abp_blocklist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/schema"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/idna"
)

func isAscii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func normalizeQname(q string) string {
	q = strings.TrimSuffix(strings.ToLower(q), ".")
	// Fast path: for pure-ASCII names (the common case) we can skip the IDNA
	// ToASCII call entirely — it only does work when non-ASCII code points
	// are present.
	if isAscii(q) {
		return q
	}
	if a, ok := toAscii(q); ok {
		return a
	}
	return q
}

var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(true),
	idna.Transitional(false),
)

func toAscii(h string) (string, bool) {
	a, err := idnaProfile.ToASCII(h)
	if err != nil {
		return "", false
	}
	return a, true
}

func extractHost(s string) string {
	// take until separator ^ or a URL/control char
	end := len(s)
	for i, r := range s {
		if r == '^' || r == '/' || r == '$' || r == '*' || r == '?' {
			end = i
			break
		}
	}
	h := strings.Trim(s[:end], ".")
	return strings.ToLower(h)
}

// splitHeader splits a header line of the form `Key: value` (already stripped
// of its leading `!`) into key and value, returning ok=false when no colon is
// present.
func splitHeader(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

// List is an immutable parsed snapshot of an ABP-format blocklist.
type List struct {
	Rule  *schema.Rule
	Block map[string]struct{}
	Allow map[string]struct{}
}

func (l *List) IsBlocked(qname string) bool {
	host := normalizeQname(qname)

	for h := host; ; {
		if _, ok := l.Allow[h]; ok {
			return false
		}
		if i := strings.IndexByte(h, '.'); i < 0 {
			break
		} else {
			h = h[i+1:]
		}
	}

	for h := host; ; {
		if _, ok := l.Block[h]; ok {
			return true
		}
		if i := strings.IndexByte(h, '.'); i < 0 {
			break
		} else {
			h = h[i+1:]
		}
	}

	return false
}

func (l *List) GetRule() *schema.Rule {
	return l.Rule
}

// FromBytes parses ABP-format blocklist content. The configured name (if
// non-empty) becomes Rule.Name; otherwise a `! Title:` header line in the
// file is used. Rule.Version is taken from a `! Version:` (or `! Last
// modified:`) header, falling back to the content hash. Rule.Id is always
// the content hash so each parsed snapshot is unique per content.
func FromBytes(name string, data []byte) (*List, error) {
	block := make(map[string]struct{}, 1<<18)
	allow := make(map[string]struct{}, 1<<16)

	var title, version, lastModified string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "!") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "!"))
			if k, v, ok := splitHeader(rest); ok {
				switch strings.ToLower(k) {
				case "title":
					title = v
				case "version":
					version = v
				case "last modified", "last-modified":
					lastModified = v
				}
			}
			continue
		}

		if strings.ContainsAny(line, "/$*") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "@@||"):
			if h := extractHost(line[4:]); h != "" {
				if a, ok := toAscii(h); ok {
					allow[a] = struct{}{}
				}
			}
		case strings.HasPrefix(line, "||"):
			if h := extractHost(line[2:]); h != "" {
				if a, ok := toAscii(h); ok {
					block[a] = struct{}{}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("scanner err: %w", err), scanner)
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	rule := &schema.Rule{Id: hash}
	switch {
	case name != "":
		rule.Name = name
	case title != "":
		rule.Name = title
	}
	switch {
	case version != "":
		rule.Version = version
	case lastModified != "":
		rule.Version = lastModified
	default:
		rule.Version = hash
	}

	return &List{Rule: rule, Block: block, Allow: allow}, nil
}

// Source is a live, reloadable view of a blocklist file on disk. It is safe
// for concurrent use; the snapshot pointer is swapped atomically and the
// resolver consumes it through the Blocklist interface (IsBlocked / GetRule).
type Source struct {
	name     string
	path     string
	snapshot atomic.Pointer[List]
}

// New creates a Source bound to path. The configured name takes precedence
// over a `! Title:` header in the file. The file is not read until Reload is
// called.
func New(name, path string) *Source {
	return &Source{name: name, path: path}
}

// Name returns the configured blocklist name.
func (s *Source) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Path returns the file path the Source was configured with.
func (s *Source) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Snapshot returns the currently loaded list, or nil if Reload has not yet
// succeeded.
func (s *Source) Snapshot() *List {
	if s == nil {
		return nil
	}
	return s.snapshot.Load()
}

// IsBlocked satisfies the resolver Blocklist interface. Before any successful
// Reload it returns false so that the resolver degrades gracefully — the
// updater can come up after the resolver and the watcher will pick the file
// up when it appears.
func (s *Source) IsBlocked(qname string) bool {
	if s == nil {
		return false
	}
	list := s.snapshot.Load()
	if list == nil {
		return false
	}
	return list.IsBlocked(qname)
}

// GetRule satisfies the resolver Blocklist interface.
func (s *Source) GetRule() *schema.Rule {
	if s == nil {
		return nil
	}
	list := s.snapshot.Load()
	if list == nil {
		return nil
	}
	return list.GetRule()
}

// Reload reads, parses, and (if the content hash differs from the current
// snapshot) atomically swaps in a new snapshot. The bool is true when a new
// snapshot was installed, false when the file content was identical and the
// existing snapshot was kept.
func (s *Source) Reload() (bool, error) {
	if s == nil {
		return false, nil
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return false, motmedelErrors.New(fmt.Errorf("os read file: %w", err), s.path)
	}

	list, err := FromBytes(s.name, data)
	if err != nil {
		return false, motmedelErrors.New(fmt.Errorf("from bytes: %w", err), s.path)
	}

	prev := s.snapshot.Load()
	if prev != nil && prev.Rule != nil && list.Rule != nil && prev.Rule.Id == list.Rule.Id {
		return false, nil
	}

	s.snapshot.Store(list)
	return true, nil
}

// Watch blocks until ctx is cancelled, reloading the blocklist file whenever
// it changes. The parent directory is watched (rather than the file itself)
// so that updaters that write atomically via rename are handled correctly,
// and reload errors are logged through slog instead of aborting the watch.
func (s *Source) Watch(ctx context.Context) error {
	if s == nil {
		return nil
	}

	absPath, err := filepath.Abs(s.path)
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("filepath abs: %w", err), s.path)
	}
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("fsnotify new watcher: %w", err))
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("fsnotify watcher add: %w", err), dir)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if filepath.Base(event.Name) != base {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			changed, err := s.Reload()
			if err != nil {
				slog.ErrorContext(
					motmedelContext.WithError(
						ctx,
						motmedelErrors.New(fmt.Errorf("reload: %w", err), s.name, s.path),
					),
					"",
					slog.Group(
						"event",
						slog.String("action", "blocklist_reload"),
						slog.String("reason", "An error occurred when reloading a blocklist."),
						slog.String("kind", "event"),
						slog.String("outcome", "failure"),
						slog.Any("category", []string{"file"}),
						slog.Any("type", []string{"error"}),
					),
				)
				continue
			}
			if !changed {
				slog.DebugContext(
					ctx,
					"",
					slog.Group(
						"event",
						slog.String("action", "blocklist_reload"),
						slog.String("reason", "A blocklist file change produced no content difference."),
						slog.String("kind", "event"),
						slog.String("outcome", "success"),
						slog.Any("category", []string{"file"}),
						slog.Any("type", []string{"info"}),
					),
					slog.Group("blocklist", slog.String("name", s.name), slog.String("path", s.path)),
				)
				continue
			}
			var version string
			if list := s.snapshot.Load(); list != nil && list.Rule != nil {
				version = list.Rule.Version
			}
			slog.InfoContext(
				ctx,
				"",
				slog.Group(
					"event",
					slog.String("action", "blocklist_updated"),
					slog.String("reason", "A blocklist was reloaded."),
					slog.String("kind", "event"),
					slog.String("outcome", "success"),
					slog.Any("category", []string{"file"}),
					slog.Any("type", []string{"change"}),
				),
				slog.Group(
					"blocklist",
					slog.String("name", s.name),
					slog.String("path", s.path),
					slog.String("version", version),
				),
			)
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.New(fmt.Errorf("fsnotify watcher: %w", err), s.name, s.path),
				),
				"",
				slog.Group(
					"event",
					slog.String("action", "blocklist_watch"),
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
