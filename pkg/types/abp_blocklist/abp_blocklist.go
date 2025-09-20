package abp_blocklist

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/utils"
	"golang.org/x/net/idna"
	"io"
	"strings"
)

var ErrNilList = errors.New("nil list")

func normalizeQname(q string) string {
	q = strings.TrimSuffix(strings.ToLower(q), ".")
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

type List struct {
	Rule *ecs.Rule
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

func (l *List) GetRule() *ecs.Rule {
	return l.Rule
}

func FromReader(reader io.Reader) (*List, error) {
	if utils.IsNil(reader) {
		return nil, nil
	}

	block := make(map[string]struct{}, 1<<18)
	allow := make(map[string]struct{}, 1<<16)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") {
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

	return &List{Block: block, Allow: allow}, nil
}
