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
		slog.WarnContext(
			motmedelContext.WithErrorContextValue(
				context.Background(),
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
				context.Background(),
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
				context.Background(),
				motmedelErrors.NewWithTrace(dnsResolverErrors.ErrNilRemoteAddress),
			),
			"Empty remote address.",
		)
		return
	}

	cacheKey := getCacheKey(requestQuestions[0])
	transportProtocol := remoteAddr.Network()

	var response *dns.Msg

	response, cacheHit, remainingTtl := r.Cache.Get(cacheKey)
	if !cacheHit || response == nil {
		var err error
		var dnsContext dnsUtilsTypes.DnsContext
		ctxWithDns := dnsUtilsContext.WithDnsContextValue(r.ParentContext, &dnsContext)

		response, err = dns_utils.Exchange(ctxWithDns, request, r.Client, r.ServerAddress)
		if err != nil && !errors.Is(err, dnsUtilsErrors.ErrUnsuccessfulRcode) {
			slog.ErrorContext(
				motmedelContext.WithErrorContextValue(ctxWithDns, err),
				"An error occurred when handling a request.",
			)
			return
		}

		defer func() {
			slog.InfoContext(ctxWithDns, "A DNS request was forwarded.")
		}()

		r.Cache.Set(cacheKey, response, dnsContext.Time)
		r.Cache.StartJanitor(5 * time.Minute)
	} else {
		cacheHit = false
	}

	if response == nil {
		slog.WarnContext(
			motmedelContext.WithErrorContextValue(
				context.Background(),
				motmedelErrors.NewWithTrace(fmt.Errorf("%w (response)", dnsUtilsErrors.ErrNilMessage)),
			),
			"Empty response.",
		)
		return
	}

	if cacheHit {
		response = response.Copy()
		response.Id = request.Id
		dns_utils.ApplyRemainingTtl(response, uint32(remainingTtl))
	}

	if transportProtocol == "udp" {
		bufferSize := uint16(512)
		if opt := request.IsEdns0(); opt != nil {
			bufferSize = opt.UDPSize()
		}

		if !cacheHit {
			response = response.Copy()
		}

		response.Truncate(int(bufferSize))
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

func New(ctx context.Context, client *dns.Client, serverAddress string) (*Resolver, error) {
	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	return &Resolver{ParentContext: ctx, Client: client, ServerAddress: serverAddress, Cache: cache.New(ctx)}, nil
}
