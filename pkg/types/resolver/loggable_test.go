package resolver

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	"github.com/miekg/dns"
)

// lockedBuffer collects log output written from several goroutines.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Split(strings.TrimSpace(b.buffer.String()), "\n")
}

// productionLogger builds the handler chain main does, writing JSON to sink.
func productionLogger(sink *lockedBuffer) *slog.Logger {
	return slog.New(&altshiftLog.ContextHandler{
		Next: slog.NewJSONHandler(sink, nil),
		Extractors: []altshiftLog.ContextExtractor{
			&altshiftLog.ErrorContextExtractor{
				ContextExtractors: []altshiftLog.ContextExtractor{&motmedelDnsLog.DnsContextExtractor},
			},
			&motmedelDnsLog.DnsContextExtractor,
		},
	})
}

func bigAnswer(qtype uint16) answerFunc {
	return func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		name := query.Question[0].Name
		switch qtype {
		case dns.TypeTXT:
			strs := make([]string, 0, 240)
			for range 240 {
				strs = append(strs, strings.Repeat("t", 255))
			}
			response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: strs}}
		case dns.TypeA:
			response.Compress = true
			for i := range 3000 {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(10, byte(i>>8), byte(i), 1).To4(),
				})
			}
		}
		return response
	}
}

// A log event stays small however large the answer it describes. Every
// answer record was written out, twice, into each of the two events a
// forwarded query makes.
//
// It swaps the default logger, so it does not run in parallel; the parallel
// tests are paused while it runs.
func TestServeDNS_LogSize(t *testing.T) {
	const maxLineLength = 16 << 10

	sink := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(productionLogger(sink))
	t.Cleanup(func() { slog.SetDefault(previous) })

	testCases := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{name: "large txt", qname: "bigtxt.example.", qtype: dns.TypeTXT},
		{name: "many addresses", qname: "manya.example.", qtype: dns.TypeA},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := startUpstream(t, bigAnswer(testCase.qtype))
			resolver := newTestResolver(t, upstream)

			reply, length := askWire(resolver, "tcp", newQuery(testCase.qname, testCase.qtype))
			if reply == nil || reply.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s; want NOERROR", rcodeOf(reply))
			}
			if length < 30_000 {
				t.Fatalf("the reply is %d bytes; the test needs a large one", length)
			}

			var events int
			for _, line := range sink.lines() {
				if !strings.Contains(line, strings.TrimSuffix(testCase.qname, ".")) {
					continue
				}
				events++
				if len(line) > maxLineLength {
					t.Errorf("a log event is %d bytes; want at most %d: %.200s...", len(line), maxLineLength, line)
				}
			}
			if events < 2 {
				t.Fatalf("found %d log events for the query; want the forward and handle events", events)
			}
		})
	}
}

func TestLoggable(t *testing.T) {
	t.Parallel()

	txt := func(size int) *dns.TXT {
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{strings.Repeat("x", size)},
		}
	}
	addresses := func(count int) []dns.RR {
		var records []dns.RR
		for i := range count {
			records = append(records, &dns.A{
				Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(i)).To4(),
			})
		}
		return records
	}

	testCases := []struct {
		name        string
		answer      []dns.RR
		wantSame    bool
		wantRecords int
	}{
		{name: "small", answer: append(addresses(2), txt(100)), wantSame: true, wantRecords: 3},
		{name: "many records", answer: addresses(100), wantRecords: maxLoggedRecords},
		{name: "long text", answer: []dns.RR{txt(5000)}, wantRecords: 1},
		{
			name: "long other record",
			answer: []dns.RR{&dns.OPENPGPKEY{
				Hdr:       dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeOPENPGPKEY, Class: dns.ClassINET, Ttl: 60},
				PublicKey: strings.Repeat("QUFB", 1000),
			}},
			wantRecords: 1,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			message := new(dns.Msg)
			message.SetQuestion("a.example.", dns.TypeA)
			message.Answer = testCase.answer
			before := message.String()

			got := loggable(message)
			if (got == message) != testCase.wantSame {
				t.Fatalf("loggable returned the message itself = %t; want %t", got == message, testCase.wantSame)
			}
			if message.String() != before {
				t.Fatal("loggable changed the message it was given")
			}
			if len(got.Answer) != testCase.wantRecords {
				t.Fatalf("logged %d answers; want %d", len(got.Answer), testCase.wantRecords)
			}
			for i, record := range got.Answer {
				if length := dns.Len(record); length > maxLoggedRecordData+64 {
					t.Fatalf("a logged record is %d bytes; want about %d at most", length, maxLoggedRecordData)
				}
				if record.Header().Rrtype != testCase.answer[i].Header().Rrtype || record.Header().Name != "a.example." {
					t.Fatalf("logged record %v lost its type or owner", record)
				}
			}
		})
	}
}
