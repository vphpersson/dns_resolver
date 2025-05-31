package resolver

import (
	"context"
	dnsResolverErrors "dns_resolver/pkg/errors"
	"dns_resolver/pkg/types/cache"
	"errors"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelTlsContext "github.com/Motmedel/utils_go/pkg/tls/context"
	"github.com/miekg/dns"
	"github.com/vphpersson/connection_pool/pkg/connection_pool"
	connectionPoolErrors "github.com/vphpersson/connection_pool/pkg/errors"
	"log/slog"
	"math"
	"strings"
	"time"
)

func getCacheKey(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

type Resolver struct {
	ParentContext  context.Context
	Client         *dns.Client
	ServerAddress  string
	Cache          *cache.Cache
	ConnectionPool *connection_pool.ConnectionPool[*dns.Conn]
}

func (r *Resolver) ServeDNS(responseWriter dns.ResponseWriter, request *dns.Msg) {
	if request == nil {
		slog.WarnContext(
			motmedelContext.WithErrorContextValue(
				r.ParentContext,
				motmedelErrors.NewWithTrace(fmt.Errorf("%w (request)", dnsUtilsErrors.ErrNilMessage)),
			),
			"Empty request.",
		)
		return
	}

	requestQuestions := request.Question
	if len(requestQuestions) == 0 {
		slog.WarnContext(
			motmedelContext.WithErrorContextValue(
				r.ParentContext,
				motmedelErrors.NewWithTrace(dnsResolverErrors.ErrNoQuestions),
			),
			"No request questions.",
		)
		return
	}

	remoteAddr := responseWriter.RemoteAddr()
	if remoteAddr == nil {
		slog.WarnContext(
			motmedelContext.WithErrorContextValue(
				r.ParentContext,
				motmedelErrors.NewWithTrace(dnsResolverErrors.ErrNilRemoteAddress),
			),
			"Empty remote address.",
		)
		return
	}

	// Obtain a response.

	var response *dns.Msg
	cacheKey := getCacheKey(requestQuestions[0])

	response, cacheHit, remainingTtl := r.Cache.Get(cacheKey)
	if !cacheHit || response == nil {
		connectionPool := r.ConnectionPool
		if connectionPool == nil {
			slog.ErrorContext(
				motmedelContext.WithErrorContextValue(
					r.ParentContext,
					motmedelErrors.NewWithTrace(connectionPoolErrors.ErrNilConnectionPool),
				),
				"The connection pool is nil.",
			)
			return
		}

		for range connectionPool.MaxNumConnections + 1 {
			done := func() bool {
				var err error
				var connection *dns.Conn

				connection, err = connectionPool.Get()
				defer func() {
					connectionPool.Put(r.ParentContext, connection, err)
				}()

				if err != nil {
					slog.ErrorContext(
						motmedelContext.WithErrorContextValue(
							r.ParentContext,
							motmedelErrors.NewWithTrace(
								fmt.Errorf("connection pool get: %w", err),
								connectionPool,
							),
						),
						"An error occurred when obtaining a connection from the connection pool.",
					)
					return false
				}

				var dnsContext dnsUtilsTypes.DnsContext
				ctxWithTlsDns := motmedelTlsContext.WithTlsContext(dnsUtilsContext.WithDnsContextValue(r.ParentContext, &dnsContext))

				response, err = dns_utils.ExchangeWithConn(ctxWithTlsDns, request, r.Client, connection)
				if err == nil || errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
					slog.InfoContext(ctxWithTlsDns, "A DNS request was forwarded.")
					r.Cache.Set(cacheKey, response, dnsContext.Time)
					return true
				} else {
					if !motmedelErrors.IsClosedError(err) {
						slog.ErrorContext(
							motmedelContext.WithErrorContextValue(ctxWithTlsDns, err),
							"An error occurred when exchanging with the DNS server.",
						)
					}
					return false
				}
			}()
			if done {
				break
			}
		}
	}

	if response == nil {
		slog.ErrorContext(
			motmedelContext.WithErrorContextValue(
				r.ParentContext,
				motmedelErrors.NewWithTrace(fmt.Errorf("%w (response)", dnsUtilsErrors.ErrNilMessage)),
			),
			"Empty response.",
		)
		return
	}

	// Apply changes to the response so that it can be used with the request.

	response = response.Copy()
	response.Id = request.Id

	if cacheHit {
		dns_utils.ApplyRemainingTtl(response, uint32(max(int64(0), min(int64(remainingTtl.Seconds()), int64(math.MaxUint32)))))
	}

	transportProtocol := remoteAddr.Network()

	if transportProtocol == "udp" {
		bufferSize := uint16(512)
		if opt := request.IsEdns0(); opt != nil {
			bufferSize = opt.UDPSize()
		}

		response.Truncate(int(bufferSize))
	}

	// Write the response.

	var dnsResolverServerAddress string
	if localAddr := responseWriter.LocalAddr(); localAddr != nil {
		dnsResolverServerAddress = localAddr.String()
	}

	now := time.Now()
	ctxWithDns := dnsUtilsContext.WithDnsContextValue(
		r.ParentContext,
		&dnsUtilsTypes.DnsContext{
			Time:            &now,
			ClientAddress:   remoteAddr.String(),
			ServerAddress:   dnsResolverServerAddress,
			Transport:       transportProtocol,
			QuestionMessage: request,
			AnswerMessage:   response,
		},
	)

	if err := responseWriter.WriteMsg(response); err != nil {
		slog.ErrorContext(
			motmedelContext.WithErrorContextValue(
				ctxWithDns,
				motmedelErrors.New(fmt.Errorf("response writer write msg: %w", err), response),
			),
			"An error occurred when writing a response.",
		)

		return
	}

	slog.InfoContext(ctxWithDns, "A request was handled.")
}

func (r *Resolver) Close() error {
	if connectionPool := r.ConnectionPool; connectionPool != nil {
		if err := connectionPool.Close(); err != nil {
			return motmedelErrors.New(fmt.Errorf("connection pool close: %w", err), connectionPool)
		}
	}

	return nil
}

func New(ctx context.Context, client *dns.Client, serverAddress string) (*Resolver, error) {
	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	resolver := Resolver{
		ParentContext: ctx,
		Client:        client,
		ServerAddress: serverAddress,
		Cache:         cache.New(),
	}

	resolver.ConnectionPool = connection_pool.New[*dns.Conn](
		func() (*dns.Conn, error) {
			resolverClient := resolver.Client
			if resolverClient == nil {
				return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
			}

			resolverServerAddress := resolver.ServerAddress
			if resolverServerAddress == "" {
				return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
			}

			connection, err := resolverClient.Dial(resolverServerAddress)
			if err != nil {
				return nil, motmedelErrors.NewWithTrace(
					fmt.Errorf("client dial: %w", err),
					resolverClient,
					resolverServerAddress,
				)
			}
			if connection == nil {
				return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilConnection)
			}

			return connection, nil
		},
	)

	return &resolver, nil
}
