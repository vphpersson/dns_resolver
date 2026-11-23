package resolver

import (
	"context"
	"crypto/tls"
	dnsResolverErrors "dns_resolver/pkg/errors"
	"dns_resolver/pkg/types/cache"
	"dns_resolver/pkg/types/local_zone"
	"dns_resolver/pkg/types/resolver_config"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dns_resolver/pkg/connection_pool"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsQuic "github.com/Motmedel/dns_utils/pkg/quic"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftJson "github.com/altshiftab/utils_go/pkg/json"
	"github.com/altshiftab/utils_go/pkg/log"
	"github.com/altshiftab/utils_go/pkg/schema"
	altshiftTlsContext "github.com/altshiftab/utils_go/pkg/tls/context"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	// dialTimeout bounds establishing a new upstream DoT connection, covering
	// both the TCP and TLS handshakes. The request's own deadline bounds it too.
	dialTimeout = 5 * time.Second
	// exchangeTimeout bounds one write and one read of an upstream exchange.
	exchangeTimeout = 2 * time.Second
	// maxExchangeAttempts is how many upstream connections one request may
	// try. A second attempt covers a pooled connection the upstream closed
	// while it sat idle; beyond that a failure is the name's, not the
	// connection's, and retrying only holds more connections for longer.
	maxExchangeAttempts = 3
	// keepAlivePeriod sets the TCP keep-alive interval on upstream DoT
	// connections. It keeps idle connections warm across middleboxes/NAT and
	// surfaces dead peers promptly, so a reused-but-closed connection fails
	// fast on the next exchange instead of stalling until the read timeout.
	keepAlivePeriod = 30 * time.Second
)

// makeEventGroup builds an ECS `event` attribute group with the common
// `kind=event` and `category=[network]` defaults used throughout the resolver.
func makeEventGroup(action, reason, outcome string, eventTypes ...string) slog.Attr {
	return slog.Group(
		"event",
		slog.String("action", action),
		slog.String("reason", reason),
		slog.String("kind", "event"),
		slog.String("outcome", outcome),
		slog.Any("category", []string{"network"}),
		slog.Any("type", eventTypes),
	)
}

type Blocklist interface {
	IsBlocked(qname string) bool
	GetRule() *schema.Rule
}

// HostsResolver answers a request from a local hosts file. Implementations
// return nil when no entry matches so that the caller falls through to the
// upstream resolver.
type HostsResolver interface {
	Resolve(request *dns.Msg) *dns.Msg
}

func makeBlockedResponse(request *dns.Msg) *dns.Msg {
	if request == nil {
		return nil
	}

	requestQuestions := request.Question
	if len(requestQuestions) == 0 {
		return nil
	}

	question := requestQuestions[0]

	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeSuccess)

	response.Ns = []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "ns.block.local.",
			Mbox:    "hostmaster.block.local.",
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  3600,
		},
	}

	return response
}

func requestDO(msg *dns.Msg) bool {
	if opt := msg.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

// getCacheKey names what an answer depends on. Everything that varies the
// upstream query, which newUpstreamQuery builds from these and nothing else,
// is part of it.
func getCacheKey(q dns.Question, do bool, cd bool) cache.Key {
	return cache.Key{
		Name:   strings.ToLower(q.Name),
		Qtype:  q.Qtype,
		Qclass: q.Qclass,
		DO:     do,
		CD:     cd,
	}
}

// upstreamUDPSize is the EDNS payload size advertised upstream. The upstream is
// reached over a stream, so it bounds nothing; RFC 9715's 1232 is a safe value
// to state.
const upstreamUDPSize = 1232

// newUpstreamQuery builds the query sent upstream for a client's question. It
// is the resolver's own: the client's ID, header bits, EDNS options and other
// sections are not forwarded, since the answer is cached for every client and
// may only depend on what the cache key holds. RD is always set, as an answer
// to a query without it is whatever the upstream happens to have cached. AD is
// set so the upstream reports whether it validated the answer (RFC 6840 §5.7).
func newUpstreamQuery(question dns.Question, do bool, cd bool) *dns.Msg {
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.Opcode = dns.OpcodeQuery
	query.RecursionDesired = true
	query.AuthenticatedData = true
	query.CheckingDisabled = cd
	query.Question = []dns.Question{{
		Name:   strings.ToLower(question.Name),
		Qtype:  question.Qtype,
		Qclass: question.Qclass,
	}}
	query.SetEdns0(upstreamUDPSize, do)
	return query
}

// maxUDPSize caps the size of a UDP reply whatever the client advertised.
// 1232 is RFC 9715's value: the largest payload that fits an IPv6 datagram
// without fragmenting on a 1280-byte path. A larger answer goes over TCP.
const maxUDPSize = 1232

// replyUDPSize is the largest UDP reply the asker of request is sent, and the
// EDNS payload size the resolver advertises to it: what it advertised, held
// between 512 (RFC 6891 §6.2.5) and maxUDPSize.
func replyUDPSize(request *dns.Msg) uint16 {
	opt := request.IsEdns0()
	if opt == nil {
		return dns.MinMsgSize
	}
	return min(max(opt.UDPSize(), dns.MinMsgSize), maxUDPSize)
}

// setReplyEdns gives reply the OPT record the asker is owed: one when the
// request carried one (RFC 6891 §6.1.1), describing this resolver rather than
// whoever answered it, and none otherwise.
func setReplyEdns(reply *dns.Msg, request *dns.Msg) {
	if opt := request.IsEdns0(); opt != nil {
		reply.SetEdns0(replyUDPSize(request), opt.Do())
		return
	}
	// Without an OPT record an extended rcode cannot be expressed at all.
	if reply.Rcode > 0xF {
		reply.Rcode = dns.RcodeServerFailure
	}
}

// copyRecords deep-copies records, leaving out OPT, which belongs to whoever
// sent the message. A record owned by the queried name takes the asker's
// spelling of it, so the reply reads as an answer to the question it carries.
func copyRecords(records []dns.RR, askedName string) []dns.RR {
	if len(records) == 0 {
		return nil
	}
	copied := make([]dns.RR, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		if _, ok := record.(*dns.OPT); ok {
			continue
		}
		record = dns.Copy(record)
		if header := record.Header(); askedName != "" && strings.EqualFold(header.Name, askedName) {
			header.Name = askedName
		}
		copied = append(copied, record)
	}
	return copied
}

// buildReply makes the reply to request from answer, which may come from the
// cache, the upstream, the hosts file or a blocklist and is left unmodified.
// The reply carries the asker's own ID, opcode, RD and CD bits and question,
// and an OPT record of the resolver's; of answer it takes the rcode, the
// records and the AA, TC and AD bits. AD is kept only for an asker that said
// it understands it, by setting AD or DO (RFC 6840 §5.8).
func buildReply(request *dns.Msg, answer *dns.Msg) *dns.Msg {
	reply := new(dns.Msg)
	reply.SetRcode(request, answer.Rcode)
	// Compressed as the upstream sent it, a large answer fits the 64 KiB a
	// TCP message may take; written out in full, it might not.
	reply.Compress = true
	reply.Authoritative = answer.Authoritative
	reply.Truncated = answer.Truncated
	reply.RecursionAvailable = true
	reply.AuthenticatedData = answer.AuthenticatedData && (request.AuthenticatedData || requestDO(request))

	var askedName string
	if len(request.Question) > 0 {
		askedName = request.Question[0].Name
	}
	reply.Answer = copyRecords(answer.Answer, askedName)
	reply.Ns = copyRecords(answer.Ns, "")
	reply.Extra = copyRecords(answer.Extra, "")

	setReplyEdns(reply, request)

	return reply
}

func writeErrorResponse(responseWriter dns.ResponseWriter, request *dns.Msg, rcode int) {
	if responseWriter == nil || request == nil {
		return
	}
	response := new(dns.Msg)
	response.SetRcode(request, rcode)
	response.RecursionAvailable = true
	setReplyEdns(response, request)
	_ = responseWriter.WriteMsg(response)
}

type DotConfig struct {
	Client         *dns.Client
	ConnectionPool *connection_pool.Pool[*dns.Conn]
}

// blocklistSet is the value stored behind Resolver.blocklists. It owns both
// the name-keyed map (used for upsert and removal) and a pre-sorted slice
// (used by the read path so that ServeDNS does not allocate per query).
type blocklistSet struct {
	byName map[string]Blocklist
	list   []Blocklist
}

func newBlocklistSet(byName map[string]Blocklist) *blocklistSet {
	names := make([]string, 0, len(byName))
	for k := range byName {
		names = append(names, k)
	}
	sort.Strings(names)
	list := make([]Blocklist, 0, len(byName))
	for _, k := range names {
		list = append(list, byName[k])
	}
	return &blocklistSet{byName: byName, list: list}
}

// resolverMetrics holds the process-lifetime counters surfaced by the
// diagnostic /metrics endpoint. All fields are updated with atomic adds from
// ServeDNS and the DoT exchange path, so they are safe to read concurrently via
// Metrics.
type resolverMetrics struct {
	queriesTotal     atomic.Uint64
	responseNoerror  atomic.Uint64
	responseNxdomain atomic.Uint64
	responseServfail atomic.Uint64
	responseOther    atomic.Uint64
	blocked          atomic.Uint64
	hostsAnswered    atomic.Uint64
	localAnswered    atomic.Uint64
	upstreamErrors   atomic.Uint64
	exchangeErrors   atomic.Uint64
	overloadRejected atomic.Uint64
}

// Metrics is a point-in-time snapshot of the resolver counters plus the cache
// stats, serialised by the /metrics endpoint.
type Metrics struct {
	QueriesTotal     uint64      `json:"queries_total"`
	ResponseNoerror  uint64      `json:"response_noerror"`
	ResponseNxdomain uint64      `json:"response_nxdomain"`
	ResponseServfail uint64      `json:"response_servfail"`
	ResponseOther    uint64      `json:"response_other"`
	Blocked          uint64      `json:"blocked"`
	HostsAnswered    uint64      `json:"hosts_answered"`
	LocalAnswered    uint64      `json:"local_answered"`
	UpstreamErrors   uint64      `json:"upstream_errors"`
	ExchangeErrors   uint64      `json:"exchange_errors"`
	OverloadRejected uint64      `json:"overload_rejected"`
	Cache            cache.Stats `json:"cache"`
}

type Resolver struct {
	// LifetimeContext bounds the resolver's life, and is the context its request
	// handling derives from. It is held here rather than passed because
	// dns.Handler's ServeDNS is handed no context at all, so there is no
	// per-request context to prefer over it. Cancelling it is what lets an
	// in-flight acquisition abandon a pool that is shutting down.
	//nolint:containedctx // ServeDNS provides no context; see above.
	LifetimeContext context.Context
	ServerAddress   string
	ServerName      string
	Cache           *cache.Cache
	Mode            string
	DotConfig       *DotConfig
	Hosts           HostsResolver
	// MaintenanceInterval drives the upstream pool's keep-alive/eviction loop
	// when started via StartConnectionMaintenance (DoT mode only).
	MaintenanceInterval time.Duration
	// RequestTimeout bounds the handling of one request; <= 0 means
	// resolver_config.DefaultRequestTimeout.
	RequestTimeout time.Duration
	// forwardSlots bounds the requests waiting on the upstream at once.
	forwardSlots chan struct{}
	metrics      resolverMetrics
	blocklistsMu sync.Mutex
	blocklists   atomic.Pointer[blocklistSet]
}

// Metrics returns a snapshot of the resolver and cache counters.
func (r *Resolver) Metrics() Metrics {
	m := Metrics{
		QueriesTotal:     r.metrics.queriesTotal.Load(),
		ResponseNoerror:  r.metrics.responseNoerror.Load(),
		ResponseNxdomain: r.metrics.responseNxdomain.Load(),
		ResponseServfail: r.metrics.responseServfail.Load(),
		ResponseOther:    r.metrics.responseOther.Load(),
		Blocked:          r.metrics.blocked.Load(),
		HostsAnswered:    r.metrics.hostsAnswered.Load(),
		LocalAnswered:    r.metrics.localAnswered.Load(),
		UpstreamErrors:   r.metrics.upstreamErrors.Load(),
		ExchangeErrors:   r.metrics.exchangeErrors.Load(),
		OverloadRejected: r.metrics.overloadRejected.Load(),
	}
	if r.Cache != nil {
		m.Cache = r.Cache.Stats()
	}
	return m
}

// countResponseRcode buckets a response by its rcode for the metrics counters.
func (r *Resolver) countResponseRcode(rcode int) {
	switch rcode {
	case dns.RcodeSuccess:
		r.metrics.responseNoerror.Add(1)
	case dns.RcodeNameError:
		r.metrics.responseNxdomain.Add(1)
	case dns.RcodeServerFailure:
		r.metrics.responseServfail.Add(1)
	default:
		r.metrics.responseOther.Add(1)
	}
}

// SetBlocklist installs (or replaces) a named blocklist. The read path is
// lock-free; only writers contend on blocklistsMu, and writes are expected
// to be rare (initial load + reloads on file change).
func (r *Resolver) SetBlocklist(name string, blocklist Blocklist) {
	if name == "" || blocklist == nil {
		return
	}

	r.blocklistsMu.Lock()
	defer r.blocklistsMu.Unlock()

	cur := r.blocklists.Load()
	next := make(map[string]Blocklist, len(cur.byNameOrEmpty())+1)
	for k, v := range cur.byNameOrEmpty() {
		next[k] = v
	}
	next[name] = blocklist
	r.blocklists.Store(newBlocklistSet(next))
}

// RemoveBlocklist drops a named blocklist if present.
func (r *Resolver) RemoveBlocklist(name string) {
	r.blocklistsMu.Lock()
	defer r.blocklistsMu.Unlock()

	cur := r.blocklists.Load()
	if cur == nil {
		return
	}
	if _, ok := cur.byName[name]; !ok {
		return
	}
	next := make(map[string]Blocklist, len(cur.byName)-1)
	for k, v := range cur.byName {
		if k == name {
			continue
		}
		next[k] = v
	}
	r.blocklists.Store(newBlocklistSet(next))
}

// Blocklists returns the currently active blocklists in name order. The
// returned slice is owned by the registry and must not be modified.
func (r *Resolver) Blocklists() []Blocklist {
	if p := r.blocklists.Load(); p != nil {
		return p.list
	}
	return nil
}

// byNameOrEmpty lets SetBlocklist treat a nil pointer as an empty map without
// special-casing the first call.
func (s *blocklistSet) byNameOrEmpty() map[string]Blocklist {
	if s == nil {
		return nil
	}
	return s.byName
}

func (r *Resolver) handleDot(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	dotConfig := r.DotConfig
	if dotConfig == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dot config"))
	}

	client := dotConfig.Client
	if client == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
	}

	connectionPool := dotConfig.ConnectionPool
	if connectionPool == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("connection pool"))
	}

	var lastErr error
	for range maxExchangeAttempts {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}

		response, retry, err := r.exchangeDot(ctx, request, client, connectionPool)
		if err == nil {
			return response, nil
		}
		if !retry {
			return nil, err
		}
		lastErr = err
	}

	return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", dnsResolverErrors.ErrNoAnswer, lastErr))
}

// exchangeDot makes one attempt at an exchange over a pooled connection. retry
// reports whether another connection might fare better: false when no
// connection could be had, since the next Get would wait on the same pool.
func (r *Resolver) exchangeDot(
	ctx context.Context,
	request *dns.Msg,
	client *dns.Client,
	connectionPool *connection_pool.Pool[*dns.Conn],
) (response *dns.Msg, retry bool, err error) {
	connection, err := connectionPool.Get(ctx)
	if err != nil {
		return nil, false, altshiftErrors.New(fmt.Errorf("connection pool get: %w", err), connectionPool)
	}
	// Put closes the connection when err, as it stands when this returns, is
	// not nil.
	defer func() {
		connectionPool.Put(ctx, connection, err)
	}()

	// What a failed exchange read is not an answer, so the response is taken
	// only once the exchange has succeeded.
	exchanged, err := dns_utils.ExchangeWithConn(ctx, request, client, connection)
	trimLoggedMessages(ctx)
	if err == nil || errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
		// An rcode is the upstream's answer, not a fault of the connection.
		err = checkAnswer(request, exchanged)
		if err == nil {
			return exchanged, false, nil
		}
	}

	r.metrics.exchangeErrors.Add(1)

	if !altshiftErrors.IsClosedError(err) {
		slog.WarnContext(
			altshiftContext.WithError(ctx, err),
			"",
			makeEventGroup(
				"dns_exchange",
				"An error occurred when exchanging with the DNS server.",
				"failure",
				"connection", "protocol", "error",
			),
		)
	}

	err = fmt.Errorf("dns utils exchange with conn: %w", err)
	return nil, true, err
}

// checkAnswer reports whether response answers query: the question the
// upstream answered must be the one it was asked. A reply without a question
// section is accepted only for an rcode that is never cached, since some
// servers leave it out of an error.
func checkAnswer(query *dns.Msg, response *dns.Msg) error {
	if response == nil {
		return nil_error.New("response")
	}
	if len(query.Question) == 0 {
		return altshiftErrors.NewWithTrace(dnsResolverErrors.ErrNoQuestions)
	}

	if len(response.Question) == 0 {
		switch response.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return altshiftErrors.NewWithTrace(dnsResolverErrors.ErrAnswerMismatch, response.Rcode)
		}
		return nil
	}

	asked, answered := query.Question[0], response.Question[0]
	if len(response.Question) != 1 ||
		!strings.EqualFold(asked.Name, answered.Name) ||
		asked.Qtype != answered.Qtype ||
		asked.Qclass != answered.Qclass {
		return altshiftErrors.NewWithTrace(dnsResolverErrors.ErrAnswerMismatch, asked, answered)
	}

	return nil
}

// forward sends query to the upstream over the configured transport.
func (r *Resolver) forward(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	switch r.Mode {
	case "dot":
		return r.handleDot(ctx, query)
	case "doq":
		// RFC 9250 §4.2.1: a DoQ query's ID is zero.
		query.Id = 0
		return r.handleDoq(ctx, query)
	default:
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", dnsResolverErrors.ErrUnsupportedMode, r.Mode))
	}
}

// acquireForwardSlot takes one of the slots bounding the requests waiting on
// the upstream, reporting false when all are taken. A resolver built without
// New has no bound.
func (r *Resolver) acquireForwardSlot() bool {
	if r.forwardSlots == nil {
		return true
	}
	select {
	case r.forwardSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (r *Resolver) releaseForwardSlot() {
	if r.forwardSlots != nil {
		<-r.forwardSlots
	}
}

func (r *Resolver) handleDoq(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	if request == nil {
		return nil, nil_error.New("request")
	}

	response, err := dnsUtilsQuic.Exchange(
		ctx,
		request,
		r.ServerAddress,
		&tls.Config{NextProtos: []string{"doq"}, ServerName: r.ServerName},
		&quic.Config{
			HandshakeIdleTimeout: 5 * time.Second,
			MaxIdleTimeout:       10 * time.Second,
			KeepAlivePeriod:      2 * time.Second,
		},
	)
	if err != nil && !errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
		return nil, fmt.Errorf("dns utils quic: %w", err)
	}

	return response, nil
}

// blockingList returns the first blocklist, in name order, that blocks name,
// or nil when none does.
func (r *Resolver) blockingList(name string) Blocklist {
	for _, blocklist := range r.Blocklists() {
		if blocklist.IsBlocked(name) {
			return blocklist
		}
	}
	return nil
}

// blockedTarget returns the first blocklist blocking a name that answer's CNAME
// or DNAME records lead to, and that name.
func (r *Resolver) blockedTarget(answer *dns.Msg) (Blocklist, string) {
	for _, record := range answer.Answer {
		var target string
		switch typedRecord := record.(type) {
		case *dns.CNAME:
			target = typedRecord.Target
		case *dns.DNAME:
			target = typedRecord.Target
		default:
			continue
		}
		if blocklist := r.blockingList(target); blocklist != nil {
			return blocklist, target
		}
	}
	return nil, ""
}

// logBlocked records that blocklist blocked a request for matchedName, which
// is the question's name or one its answer leads to.
func (r *Resolver) logBlocked(ctx context.Context, blocklist Blocklist, reason string, matchedName string) {
	var args []any
	if rule := blocklist.GetRule(); rule != nil {
		ruleMap, err := altshiftJson.ObjectToMap(rule)
		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(ctx, err),
				"",
				makeEventGroup(
					"rule_serialize",
					"An error occurred when converting a rule to a map.",
					"failure",
					"error",
				),
			)
		} else {
			args = log.AttrsFromMap(ruleMap)
		}
	}

	slog.With(
		slog.Group("rule", args...),
	).WarnContext(
		ctx,
		"",
		makeEventGroup(
			"dns_request_block",
			reason,
			"success",
			"connection", "protocol", "denied",
		),
		slog.Group("blocklist", slog.String("matched_name", strings.TrimSuffix(matchedName, "."))),
	)
}

func (r *Resolver) ServeDNS(responseWriter dns.ResponseWriter, request *dns.Msg) {
	if request == nil {
		slog.WarnContext(
			altshiftContext.WithError(
				r.LifetimeContext,
				altshiftErrors.NewWithTrace(nil_error.New("request")),
			),
			"",
			makeEventGroup(
				"dns_request_validate",
				"Empty request.",
				"failure",
				"protocol", "error",
			),
		)
		return
	}

	requestQuestions := request.Question
	if len(requestQuestions) == 0 {
		slog.WarnContext(
			altshiftContext.WithError(
				r.LifetimeContext,
				altshiftErrors.NewWithTrace(dnsResolverErrors.ErrNoQuestions),
			),
			"",
			makeEventGroup(
				"dns_request_validate",
				"No request questions.",
				"failure",
				"protocol", "error",
			),
		)
		return
	}

	remoteAddr := responseWriter.RemoteAddr()
	if remoteAddr == nil {
		slog.WarnContext(
			altshiftContext.WithError(
				r.LifetimeContext,
				altshiftErrors.NewWithTrace(nil_error.New("remote address")),
			),
			"",
			makeEventGroup(
				"dns_request_validate",
				"Empty remote address.",
				"failure",
				"error",
			),
		)
		return
	}
	remoteAddrString := remoteAddr.String()
	transportProtocol := remoteAddr.Network()

	var dnsResolverServerAddress string
	if localAddr := responseWriter.LocalAddr(); localAddr != nil {
		dnsResolverServerAddress = localAddr.String()
	}

	// Obtain a response.

	question := requestQuestions[0]

	r.metrics.queriesTotal.Add(1)

	// Only a standard query is answered. Anything else -- a NOTIFY, an
	// UPDATE -- would otherwise be forwarded, and its reply cached as the
	// answer to an ordinary query for the same name.
	if request.Opcode != dns.OpcodeQuery {
		slog.WarnContext(
			r.LifetimeContext,
			"",
			makeEventGroup(
				"dns_request_validate",
				"The request's opcode is not supported.",
				"failure",
				"protocol", "denied",
			),
			slog.Group("dns", slog.String("op_code", dns.OpcodeToString[request.Opcode])),
		)
		r.metrics.responseOther.Add(1)
		writeErrorResponse(responseWriter, request, dns.RcodeNotImplemented)
		return
	}

	requestTimeout := r.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = resolver_config.DefaultRequestTimeout
	}
	requestCtx, cancelRequest := context.WithTimeout(r.LifetimeContext, requestTimeout)
	defer cancelRequest()

	do := requestDO(request)
	cacheKey := getCacheKey(question, do, request.CheckingDisabled)

	// The hosts file and the blocklists are consulted before the cache, so that
	// a change to either applies at once rather than once the cached answer
	// expires.
	var response *dns.Msg
	var cacheHit, forwarded bool
	var remainingTtl time.Duration

	if r.Hosts != nil {
		if hostsResponse := r.Hosts.Resolve(request); hostsResponse != nil {
			ctxWithDns := dnsUtilsContext.WithDnsContextValue(
				r.LifetimeContext,
				&dnsUtilsTypes.DnsContext{
					Time:            new(time.Now()),
					ClientAddress:   remoteAddrString,
					ServerAddress:   dnsResolverServerAddress,
					Transport:       transportProtocol,
					QuestionMessage: loggable(request),
					AnswerMessage:   loggable(hostsResponse),
				},
			)

			slog.InfoContext(
				ctxWithDns,
				"",
				makeEventGroup(
					"dns_request_hosts",
					"A DNS request was answered from the hosts file.",
					"success",
					"connection", "protocol", "info",
				),
			)

			r.metrics.hostsAnswered.Add(1)
			response = hostsResponse
		}
	}

	// A special-use name, or the reverse of a private address, is answered
	// here: the upstream could only say it does not exist, and asking it
	// would tell it a LAN host's name or address.
	if response == nil && question.Qclass == dns.ClassINET {
		if zone, ok := local_zone.Match(question.Name, question.Qtype); ok {
			localResponse := local_zone.Response(request, zone)
			slog.InfoContext(
				dnsUtilsContext.WithDnsContextValue(
					r.LifetimeContext,
					&dnsUtilsTypes.DnsContext{
						Time:            new(time.Now()),
						ClientAddress:   remoteAddrString,
						ServerAddress:   dnsResolverServerAddress,
						Transport:       transportProtocol,
						QuestionMessage: loggable(request),
						AnswerMessage:   loggable(localResponse),
					},
				),
				"",
				makeEventGroup(
					"dns_request_local",
					"A request for a special-use or private name was answered locally.",
					"success",
					"connection", "protocol", "info",
				),
			)
			r.metrics.localAnswered.Add(1)
			response = localResponse
		}
	}

	if response == nil {
		if blocklist := r.blockingList(question.Name); blocklist != nil {
			r.logBlocked(
				dnsUtilsContext.WithDnsContextValue(
					r.LifetimeContext,
					&dnsUtilsTypes.DnsContext{
						Time:            new(time.Now()),
						ClientAddress:   remoteAddrString,
						ServerAddress:   dnsResolverServerAddress,
						Transport:       transportProtocol,
						QuestionMessage: loggable(request),
					},
				),
				blocklist,
				"A DNS request was blocked by a blocklist.",
				question.Name,
			)
			r.metrics.blocked.Add(1)
			response = makeBlockedResponse(request)
		}
	}

	if response == nil {
		response, cacheHit, remainingTtl = r.Cache.Get(cacheKey)
		if !cacheHit {
			response = nil
		}
	}

	if response == nil {
		var dnsContext dnsUtilsTypes.DnsContext
		ctxWithTlsDns := altshiftTlsContext.WithTlsContext(dnsUtilsContext.WithDnsContextValue(requestCtx, &dnsContext))

		query := newUpstreamQuery(question, do, request.CheckingDisabled)

		// A request waiting on the upstream holds a slot until it is
		// answered or its deadline passes. With every slot taken it is
		// refused at once, rather than adding another goroutine to the
		// queue for a pooled connection; what the cache, the hosts file
		// or a blocklist can answer is still answered.
		if !r.acquireForwardSlot() {
			slog.WarnContext(
				ctxWithTlsDns,
				"",
				makeEventGroup(
					"dns_request_forward",
					"The limit on requests waiting on the upstream was reached.",
					"failure",
					"connection", "denied",
				),
			)
			r.metrics.overloadRejected.Add(1)
			r.metrics.responseServfail.Add(1)
			writeErrorResponse(responseWriter, request, dns.RcodeServerFailure)
			return
		}
		defer r.releaseForwardSlot()

		var err error
		response, err = r.forward(ctxWithTlsDns, query)
		trimLoggedMessages(ctxWithTlsDns)

		if err != nil {
			slog.ErrorContext(
				altshiftContext.WithError(
					ctxWithTlsDns,
					altshiftErrors.New(fmt.Errorf("handle: %w", err), query),
				),
				"",
				makeEventGroup(
					"dns_request_forward",
					"An error occurred when handling a request.",
					"failure",
					"connection", "protocol", "error",
				),
			)
			r.metrics.upstreamErrors.Add(1)
			r.metrics.responseServfail.Add(1)
			writeErrorResponse(responseWriter, request, dns.RcodeServerFailure)
			return
		}

		if response != nil {
			slog.InfoContext(
				ctxWithTlsDns,
				"",
				makeEventGroup(
					"dns_request_forward",
					"A DNS request was forwarded.",
					"success",
					"connection", "protocol", "info",
				),
			)

			if do {
				if response.Rcode == dns.RcodeServerFailure {
					slog.WarnContext(
						ctxWithTlsDns,
						"",
						makeEventGroup(
							"dnssec_validation",
							"The upstream returned SERVFAIL for a DNSSEC-enabled query.",
							"failure",
							"connection", "protocol", "error",
						),
					)
				} else if response.AuthenticatedData {
					slog.InfoContext(
						ctxWithTlsDns,
						"",
						makeEventGroup(
							"dnssec_validation",
							"The upstream authenticated the response (AD=1).",
							"success",
							"connection", "protocol", "info",
						),
					)
				}
			}

			r.Cache.Set(cacheKey, response, dnsContext.Time)
			forwarded = true
		}
	}

	// An answer can lead to a name of its own through CNAME or DNAME records,
	// which is how a tracker is put behind a first-party name. Checked here
	// rather than when the answer was cached, a name listed since is caught.
	if response != nil && (cacheHit || forwarded) {
		if blocklist, target := r.blockedTarget(response); blocklist != nil {
			r.logBlocked(
				dnsUtilsContext.WithDnsContextValue(
					r.LifetimeContext,
					&dnsUtilsTypes.DnsContext{
						Time:            new(time.Now()),
						ClientAddress:   remoteAddrString,
						ServerAddress:   dnsResolverServerAddress,
						Transport:       transportProtocol,
						QuestionMessage: loggable(request),
					},
				),
				blocklist,
				"A name the answer leads to was blocked by a blocklist.",
				target,
			)
			r.metrics.blocked.Add(1)
			response = makeBlockedResponse(request)
			cacheHit = false
		}
	}

	if response == nil {
		slog.ErrorContext(
			altshiftContext.WithError(
				r.LifetimeContext,
				altshiftErrors.NewWithTrace(nil_error.New("response")),
			),
			"",
			makeEventGroup(
				"dns_response_validate",
				"Empty response.",
				"failure",
				"protocol", "error",
			),
		)
		r.metrics.responseServfail.Add(1)
		writeErrorResponse(responseWriter, request, dns.RcodeServerFailure)
		return
	}

	r.countResponseRcode(response.Rcode)

	// Make the reply to this asker out of the response, which is shared.

	response = buildReply(request, response)

	if cacheHit {
		dns_utils.ApplyRemainingTtl(response, uint32(max(int64(0), min(int64(remainingTtl.Seconds()), int64(math.MaxUint32)))))
	}

	if strings.HasPrefix(transportProtocol, "udp") {
		response.Truncate(int(replyUDPSize(request)))
	}

	// Write the response.

	ctxWithDns := dnsUtilsContext.WithDnsContextValue(
		r.LifetimeContext,
		&dnsUtilsTypes.DnsContext{
			Time:            new(time.Now()),
			ClientAddress:   remoteAddr.String(),
			ServerAddress:   dnsResolverServerAddress,
			Transport:       transportProtocol,
			QuestionMessage: loggable(request),
			AnswerMessage:   loggable(response),
		},
	)

	if err := responseWriter.WriteMsg(response); err != nil {
		slog.ErrorContext(
			altshiftContext.WithError(
				ctxWithDns,
				altshiftErrors.New(fmt.Errorf("response writer write msg: %w", err), response.Question),
			),
			"",
			makeEventGroup(
				"dns_response_write",
				"An error occurred when writing a response.",
				"failure",
				"connection", "error",
			),
		)

		return
	}

	slog.InfoContext(
		ctxWithDns,
		"",
		makeEventGroup(
			"dns_request_handle",
			"A request was handled.",
			"success",
			"connection", "protocol", "info",
		),
	)
}

func (r *Resolver) Close() error {
	dotConfig := r.DotConfig
	if dotConfig == nil {
		return nil
	}

	connectionPool := dotConfig.ConnectionPool
	if connectionPool == nil {
		return nil
	}

	if err := connectionPool.Close(); err != nil {
		return altshiftErrors.New(fmt.Errorf("connection pool close: %w", err), connectionPool)
	}

	return nil
}

// StartConnectionMaintenance runs the upstream connection pool's maintenance
// loop (idle eviction, keep-alive pings, warm replenishment) until ctx is
// cancelled. It is a no-op outside DoT mode or when the maintenance interval is
// not positive. Intended to be run in its own goroutine.
func (r *Resolver) StartConnectionMaintenance(ctx context.Context) {
	if r.MaintenanceInterval <= 0 {
		return
	}
	dotConfig := r.DotConfig
	if dotConfig == nil || dotConfig.ConnectionPool == nil {
		return
	}
	dotConfig.ConnectionPool.StartMaintenance(ctx, r.MaintenanceInterval)
}

// New constructs a Resolver. Options tune the resolver's settings; in
// particular WithMaxConnections bounds the number of concurrent upstream DoT
// connections held by the connection pool (a value <= 0 leaves the pool's own
// default in place, and it has no effect in "doq" mode).
func New(ctx context.Context, mode string, serverAddress string, serverName string, options ...resolver_config.Option) (*Resolver, error) {
	if mode == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("mode"))
	}

	if serverAddress == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("dns server"))
	}

	config := resolver_config.New(options...)

	resolver := Resolver{
		LifetimeContext: ctx,
		ServerAddress:   serverAddress,
		ServerName:      serverName,
		Cache: cache.New(
			cache.WithMaxEntries(config.CacheMaxEntries),
			cache.WithMaxBytes(config.CacheMaxBytes),
		),
		Mode:           mode,
		RequestTimeout: config.RequestTimeout,
	}
	if config.MaxInFlight > 0 {
		resolver.forwardSlots = make(chan struct{}, config.MaxInFlight)
	}

	switch mode {
	case "dot":
		// Share a TLS session cache across dials so reconnects resume rather
		// than perform a full handshake. Verification still pins to serverName
		// when set, otherwise to the dial host (Go fills it in).
		tlsConfig := &tls.Config{
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		}
		if serverName != "" {
			tlsConfig.ServerName = serverName
		}
		client := &dns.Client{
			Net: "tcp-tls",
			Dialer: &net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: keepAlivePeriod,
			},
			TLSConfig:    tlsConfig,
			ReadTimeout:  exchangeTimeout,
			WriteTimeout: exchangeTimeout,
		}
		connectionPool := connection_pool.New[*dns.Conn](
			func(ctx context.Context) (*dns.Conn, error) {
				if client == nil {
					return nil, altshiftErrors.NewWithTrace(nil_error.New("dns client"))
				}

				resolverServerAddress := resolver.ServerAddress
				if resolverServerAddress == "" {
					return nil, altshiftErrors.NewWithTrace(empty_error.New("dns server"))
				}

				connection, err := client.DialContext(ctx, resolverServerAddress)
				if err != nil {
					return nil, altshiftErrors.NewWithTrace(
						fmt.Errorf("client dial context: %w", err),
						client,
						resolverServerAddress,
					)
				}
				if connection == nil {
					return nil, altshiftErrors.NewWithTrace(nil_error.New("connection"))
				}

				return connection, nil
			},
		)
		if config.MaxConnections > 0 {
			connectionPool.MaxNumConnections = config.MaxConnections
		}
		connectionPool.IdleTimeout = config.IdleTimeout
		connectionPool.MinIdleConnections = config.MinIdleConnections
		connectionPool.Ping = func(connection *dns.Conn) error {
			if connection == nil {
				return altshiftErrors.NewWithTrace(nil_error.New("connection"))
			}
			// A lightweight query keeps the connection alive (resetting the
			// upstream's idle timer) and confirms it is still usable. Only a
			// transport error marks it dead; any rcode is fine, so the bare
			// miekg exchange is used rather than dns_utils.ExchangeWithConn.
			pingMessage := new(dns.Msg)
			pingMessage.SetQuestion(".", dns.TypeNS)
			_, _, err := client.ExchangeWithConn(pingMessage, connection)
			return err
		}
		resolver.MaintenanceInterval = config.KeepAliveInterval
		resolver.DotConfig = &DotConfig{
			Client:         client,
			ConnectionPool: connectionPool,
		}
	case "doq":
	default:
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", dnsResolverErrors.ErrUnsupportedMode, mode))
	}

	return &resolver, nil
}
