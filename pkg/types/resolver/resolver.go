package resolver

import (
	"context"
	"crypto/tls"
	dnsResolverErrors "dns_resolver/pkg/errors"
	"dns_resolver/pkg/types/cache"
	"errors"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsQuic "github.com/Motmedel/dns_utils/pkg/quic"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelTlsContext "github.com/Motmedel/utils_go/pkg/tls/context"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
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

type DotConfig struct {
	Client         *dns.Client
	ConnectionPool *connection_pool.ConnectionPool[*dns.Conn]
}

type Resolver struct {
	ParentContext context.Context
	ServerAddress string
	ServerName    string
	Cache         *cache.Cache
	Mode          string
	DotConfig     *DotConfig
}

func (r *Resolver) handleDot(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	dotConfig := r.DotConfig
	if dotConfig == nil {
		return nil, motmedelErrors.NewWithTrace(dnsResolverErrors.ErrNilDotConfig)
	}

	client := dotConfig.Client
	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	connectionPool := dotConfig.ConnectionPool
	if connectionPool == nil {
		return nil, motmedelErrors.NewWithTrace(connectionPoolErrors.ErrNilConnectionPool)
	}

	var response *dns.Msg

	for range connectionPool.MaxNumConnections + 1 {
		done, err := func() (bool, error) {
			var err error
			var connection *dns.Conn

			connection, err = connectionPool.Get()
			if err != nil {
				return false, motmedelErrors.New(fmt.Errorf("connection pool get: %w", err), connectionPool)
			}
			defer func() {
				connectionPool.Put(ctx, connection, err)
			}()

			response, err = dns_utils.ExchangeWithConn(ctx, request, client, connection)
			if err == nil || errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
				return true, nil
			} else {
				if !motmedelErrors.IsClosedError(err) {
					slog.WarnContext(
						motmedelContext.WithErrorContextValue(ctx, err),
						"An error occurred when exchanging with the DNS server.",
					)
				}
				return false, nil
			}
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
		return nil, fmt.Errorf("%w (request)", dnsUtilsErrors.ErrNilMessage)
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
				motmedelContext.WithErrorContextValue(
					ctxWithTlsDns,
					motmedelErrors.NewWithTrace(fmt.Errorf("%w: %s", dnsResolverErrors.ErrUnsupportedMode, r.Mode)),
				),
				"Unsupported mode.",
			)
			return
		}

		if err != nil {
			slog.ErrorContext(
				motmedelContext.WithErrorContextValue(
					ctxWithTlsDns,
					motmedelErrors.New(fmt.Errorf("handle: %w", err), request),
				),
				"An error occurred when handling a request.",
			)
			return
		}

		if response != nil {
			slog.InfoContext(ctxWithTlsDns, "A DNS request was forwarded.")
			r.Cache.Set(cacheKey, response, dnsContext.Time)
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
		return nil, motmedelErrors.NewWithTrace(dnsResolverErrors.ErrEmptyMode)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	resolver := Resolver{
		ParentContext: ctx,
		ServerAddress: serverAddress,
		ServerName: serverName,
		Cache: cache.New(),
		Mode: mode,
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
						return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
					}

					resolverServerAddress := resolver.ServerAddress
					if resolverServerAddress == "" {
						return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
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
						return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilConnection)
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
