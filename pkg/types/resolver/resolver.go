package resolver

import (
	"context"
	"crypto/tls"
	dnsResolverErrors "dns_resolver/pkg/errors"
	"dns_resolver/pkg/types/cache"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync/atomic"
	"time"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsQuic "github.com/Motmedel/dns_utils/pkg/quic"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	"github.com/Motmedel/utils_go/pkg/log"
	"github.com/Motmedel/utils_go/pkg/schema"
	motmedelTlsContext "github.com/Motmedel/utils_go/pkg/tls/context"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/vphpersson/connection_pool/pkg/connection_pool"
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
	response.SetRcode(request, dns.RcodeNameError)

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
			Serial:  uint32(time.Now().Unix()),
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  3600,
		},
	}

	return response
}

func getCacheKey(q dns.Question) cache.Key {
	return cache.Key{
		Name:   strings.ToLower(q.Name),
		Qtype:  q.Qtype,
		Qclass: q.Qclass,
	}
}

func writeErrorResponse(responseWriter dns.ResponseWriter, request *dns.Msg, rcode int) {
	if responseWriter == nil || request == nil {
		return
	}
	response := new(dns.Msg)
	response.SetRcode(request, rcode)
	_ = responseWriter.WriteMsg(response)
}

type DotConfig struct {
	Client         *dns.Client
	ConnectionPool *connection_pool.Pool[*dns.Conn]
}

type Resolver struct {
	ParentContext context.Context
	ServerAddress string
	ServerName    string
	Cache         *cache.Cache
	Mode          string
	DotConfig     *DotConfig
	Hosts         HostsResolver
	blocklists    atomic.Pointer[[]Blocklist]
}

func (r *Resolver) SetBlocklists(blocklists []Blocklist) {
	r.blocklists.Store(&blocklists)
}

func (r *Resolver) Blocklists() []Blocklist {
	if p := r.blocklists.Load(); p != nil {
		return *p
	}
	return nil
}

func (r *Resolver) handleDot(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	dotConfig := r.DotConfig
	if dotConfig == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("dot config"))
	}

	client := dotConfig.Client
	if client == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("dns client"))
	}

	connectionPool := dotConfig.ConnectionPool
	if connectionPool == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("connection pool"))
	}

	var response *dns.Msg

	for range connectionPool.MaxNumConnections + 1 {
		done, err := func() (bool, error) {
			var err error
			var connection *dns.Conn

			connection, err = connectionPool.Get(ctx)
			if err != nil {
				return false, motmedelErrors.New(fmt.Errorf("connection pool get: %w", err), connectionPool)
			}
			defer func() {
				connectionPool.Put(ctx, connection, err)
			}()

			response, err = dns_utils.ExchangeWithConn(ctx, request, client, connection)
			if err == nil || errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
				return true, nil
			}

			if !motmedelErrors.IsClosedError(err) {
				slog.WarnContext(
					motmedelContext.WithError(ctx, err),
					"",
					makeEventGroup(
						"dns_exchange",
						"An error occurred when exchanging with the DNS server.",
						"failure",
						"connection", "protocol", "error",
					),
				)
			}

			return false, nil
		}()
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
	}

	return response, nil
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

func (r *Resolver) ServeDNS(responseWriter dns.ResponseWriter, request *dns.Msg) {
	if request == nil {
		slog.WarnContext(
			motmedelContext.WithError(
				r.ParentContext,
				motmedelErrors.NewWithTrace(nil_error.New("request")),
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
			motmedelContext.WithError(
				r.ParentContext,
				motmedelErrors.NewWithTrace(dnsResolverErrors.ErrNoQuestions),
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
			motmedelContext.WithError(
				r.ParentContext,
				motmedelErrors.NewWithTrace(nil_error.New("remote address")),
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

	var response *dns.Msg
	cacheKey := getCacheKey(question)
	response, cacheHit, remainingTtl := r.Cache.Get(cacheKey)
	if !cacheHit || response == nil {
		if r.Hosts != nil {
			if hostsResponse := r.Hosts.Resolve(request); hostsResponse != nil {
				ctxWithDns := dnsUtilsContext.WithDnsContextValue(
					r.ParentContext,
					&dnsUtilsTypes.DnsContext{
						Time:            new(time.Now()),
						ClientAddress:   remoteAddrString,
						ServerAddress:   dnsResolverServerAddress,
						Transport:       transportProtocol,
						QuestionMessage: request,
						AnswerMessage:   hostsResponse,
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

				response = hostsResponse
			}
		}

		if response == nil {
			var blockedByAnyList bool
			for _, blocklist := range r.Blocklists() {
				if !blocklist.IsBlocked(question.Name) {
					continue
				}
				blockedByAnyList = true

				ctxWithDns := dnsUtilsContext.WithDnsContextValue(
					r.ParentContext,
					&dnsUtilsTypes.DnsContext{
						Time:            new(time.Now()),
						ClientAddress:   remoteAddrString,
						ServerAddress:   dnsResolverServerAddress,
						Transport:       transportProtocol,
						QuestionMessage: request,
					},
				)

				var args []any

				if rule := blocklist.GetRule(); rule != nil {
					ruleMap, err := motmedelJson.ObjectToMap(rule)
					if err != nil {
						slog.ErrorContext(
							motmedelContext.WithError(ctxWithDns, err),
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
					ctxWithDns,
					"",
					makeEventGroup(
						"dns_request_block",
						"A DNS request was blocked by a blocklist.",
						"success",
						"connection", "protocol", "denied",
					),
				)
				break
			}

			if blockedByAnyList {
				response = makeBlockedResponse(request)
			}
		}

		if response == nil {
			var dnsContext dnsUtilsTypes.DnsContext
			ctxWithTlsDns := motmedelTlsContext.WithTlsContext(dnsUtilsContext.WithDnsContextValue(r.ParentContext, &dnsContext))

			var err error
			switch r.Mode {
			case "dot":
				response, err = r.handleDot(ctxWithTlsDns, request)
			case "doq":
				response, err = r.handleDoq(ctxWithTlsDns, request)
			default:
				slog.ErrorContext(
					motmedelContext.WithError(
						ctxWithTlsDns,
						motmedelErrors.NewWithTrace(fmt.Errorf("%w: %s", dnsResolverErrors.ErrUnsupportedMode, r.Mode)),
					),
					"",
					makeEventGroup(
						"dns_request_forward",
						"Unsupported mode.",
						"failure",
						"error",
					),
				)
				writeErrorResponse(responseWriter, request, dns.RcodeServerFailure)
				return
			}

			if err != nil {
				slog.ErrorContext(
					motmedelContext.WithError(
						ctxWithTlsDns,
						motmedelErrors.New(fmt.Errorf("handle: %w", err), request),
					),
					"",
					makeEventGroup(
						"dns_request_forward",
						"An error occurred when handling a request.",
						"failure",
						"connection", "protocol", "error",
					),
				)
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
				r.Cache.Set(cacheKey, response, dnsContext.Time)
			}
		}
	}

	if response == nil {
		slog.ErrorContext(
			motmedelContext.WithError(
				r.ParentContext,
				motmedelErrors.NewWithTrace(nil_error.New("response")),
			),
			"",
			makeEventGroup(
				"dns_response_validate",
				"Empty response.",
				"failure",
				"protocol", "error",
			),
		)
		writeErrorResponse(responseWriter, request, dns.RcodeServerFailure)
		return
	}

	// Apply changes to the response so that it can be used with the request.

	response = response.Copy()
	response.Id = request.Id

	if cacheHit {
		dns_utils.ApplyRemainingTtl(response, uint32(max(int64(0), min(int64(remainingTtl.Seconds()), int64(math.MaxUint32)))))
	}

	if strings.HasPrefix(transportProtocol, "udp") {
		bufferSize := uint16(512)
		if opt := request.IsEdns0(); opt != nil {
			bufferSize = opt.UDPSize()
		}

		response.Truncate(int(bufferSize))
	}

	// Write the response.

	ctxWithDns := dnsUtilsContext.WithDnsContextValue(
		r.ParentContext,
		&dnsUtilsTypes.DnsContext{
			Time:            new(time.Now()),
			ClientAddress:   remoteAddr.String(),
			ServerAddress:   dnsResolverServerAddress,
			Transport:       transportProtocol,
			QuestionMessage: request,
			AnswerMessage:   response,
		},
	)

	if err := responseWriter.WriteMsg(response); err != nil {
		slog.ErrorContext(
			motmedelContext.WithError(
				ctxWithDns,
				motmedelErrors.New(fmt.Errorf("response writer write msg: %w", err), response),
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
		return motmedelErrors.New(fmt.Errorf("connection pool close: %w", err), connectionPool)
	}

	return nil
}

func New(ctx context.Context, mode string, serverAddress string, serverName string) (*Resolver, error) {
	if mode == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("mode"))
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("dns server"))
	}

	resolver := Resolver{
		ParentContext: ctx,
		ServerAddress: serverAddress,
		ServerName:    serverName,
		Cache:         cache.New(),
		Mode:          mode,
	}

	switch mode {
	case "dot":
		client := &dns.Client{Net: "tcp-tls"}
		if serverName != "" {
			client.TLSConfig = &tls.Config{ServerName: serverName}
		}
		resolver.DotConfig = &DotConfig{
			Client: client,
			ConnectionPool: connection_pool.New[*dns.Conn](
				func() (*dns.Conn, error) {
					if client == nil {
						return nil, motmedelErrors.NewWithTrace(nil_error.New("dns client"))
					}

					resolverServerAddress := resolver.ServerAddress
					if resolverServerAddress == "" {
						return nil, motmedelErrors.NewWithTrace(empty_error.New("dns server"))
					}

					connection, err := client.Dial(resolverServerAddress)
					if err != nil {
						return nil, motmedelErrors.NewWithTrace(
							fmt.Errorf("client dial: %w", err),
							client,
							resolverServerAddress,
						)
					}
					if connection == nil {
						return nil, motmedelErrors.NewWithTrace(nil_error.New("connection"))
					}

					return connection, nil
				},
			),
		}
	case "doq":
	default:
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("%w: %s", dnsResolverErrors.ErrUnsupportedMode, mode))
	}

	return &resolver, nil
}
