package main

import (
	"context"
	"dns_resolver/pkg/types/resolver"
	"fmt"
	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"os"
	"time"
)

func main() {
	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: ecs.TimestampReplaceAttr,
					},
				),
				Extractors: []motmedelLog.ContextExtractor{
					&motmedelLog.ErrorContextExtractor{},
					&motmedelDnsLog.DnsContextExtractor,
				},
			},
		).With(slog.Group("event", slog.String("dataset", "dns_resolver"))),
	}
	slog.SetDefault(logger.Logger)

	remoteTcpServerAddress := "1.1.1.1:853"

	errGroup, errGroupCtx := errgroup.WithContext(context.Background())

	tcpResolver, err := resolver.New(errGroupCtx, &dns.Client{Net: "tcp-tls"}, remoteTcpServerAddress)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when creating the TCP resolver.",
			err,
			remoteTcpServerAddress,
		)
	}

	tcpResolver.Cache.StartJanitor(5 * time.Minute)

	// TODO: Add (diagnostic) HTTP server as well?

	for _, localServerAddress := range []string{"127.0.0.1:53", "192.168.1.1:53", "192.168.1.2:53", "192.168.1.3:53"} {
		for _, transportProtocol := range []string{"udp", "tcp"} {
			errGroup.Go(
				func() error {
					server := &dns.Server{Addr: localServerAddress, Net: transportProtocol, Handler: tcpResolver}
					if err := server.ListenAndServe(); err != nil {
						return motmedelErrors.NewWithTrace(
							fmt.Errorf("dns server listen and serve (%s): %w", transportProtocol, err),
							localServerAddress,
						)
					}
					return nil
				},
			)
		}
	}

	if err := errGroup.Wait(); err != nil {
		logger.FatalWithExitingMessage("A server error occurred.", err)
	}
}
