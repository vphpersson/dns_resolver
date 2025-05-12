package resolver

import (
	"context"
	"dns_resolver/pkg/types/cache"
	"errors"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
	"log/slog"
	"strings"
	"time"
)

func getCacheKey(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

type Resolver struct {
	ParentContext context.Context
	Client        *dns.Client
	ServerAddress string
	Cache         *cache.Cache
}

func (r *Resolver) ServeDNS(responseWriter dns.ResponseWriter, request *dns.Msg) {
	if request == nil {
		slog.Warn("Empty request.")
		return
	}

	requestQuestions := request.Question
	if len(requestQuestions) == 0 {
		slog.Warn("No request questions.")
		return
	}

	remoteAddr := responseWriter.RemoteAddr()
	if remoteAddr == nil {
		slog.Error("No remote address.")
		return
	}

	cacheKey := getCacheKey(requestQuestions[0])
	transportProtocol := remoteAddr.Network()
	var forwardedCtxWithDns *context.Context

	var response *dns.Msg

	if cachedResponseCopy, ok := r.Cache.Get(cacheKey); ok {
		cachedResponseCopy.Id = request.Id

		if transportProtocol == "udp" {
			bufferSize := uint16(512)
			if opt := request.IsEdns0(); opt != nil {
				bufferSize = opt.UDPSize()
			}

			cachedResponseCopy.Truncate(int(bufferSize))
		}

		response = cachedResponseCopy
	} else {
		var err error
		ctxWithDns := dnsUtilsContext.WithDnsContext(r.ParentContext)
		forwardedCtxWithDns = &ctxWithDns

		response, err = dns_utils.Exchange(ctxWithDns, request, r.Client, r.ServerAddress)
		if err != nil && !errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
			slog.ErrorContext(
				motmedelContext.WithErrorContextValue(ctxWithDns, err),
				"An error occurred when handling a request.",
			)
			return
		}

		r.Cache.Set(cacheKey, response)
		r.Cache.StartJanitor(5 * time.Minute)
	}

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

	var writeErr error

	defer func() {
		if ctx := forwardedCtxWithDns; ctx != nil {
			slog.InfoContext(*ctx, "A DNS request was forwarded.")
		}

		if writeErr == nil {
			slog.InfoContext(ctxWithDns, "A request was handled.")
		}
	}()

	if response == nil {
		writeErr = fmt.Errorf("%w (response)", dnsUtilsErrors.ErrNilMessage)
	} else {
		writeErr = responseWriter.WriteMsg(response)
		if writeErr != nil {
			slog.ErrorContext(
				motmedelContext.WithErrorContextValue(
					ctxWithDns,
					motmedelErrors.New(fmt.Errorf("response writer write msg: %w", writeErr), response),
				),
				"An error occurred when writing a response.",
			)
		}
	}
}

func New(ctx context.Context, client *dns.Client, serverAddress string) (*Resolver, error) {
	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	return &Resolver{ParentContext: ctx, Client: client, ServerAddress: serverAddress, Cache: cache.New(ctx)}, nil
}
