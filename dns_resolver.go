package main

import (
	"context"
	"dns_resolver/pkg/types/resolver"
	"errors"
	"fmt"
	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/miekg/dns"
	"github.com/vphpersson/argp/pkg/argp"
	argpErrors "github.com/vphpersson/argp/pkg/errors"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"os"
	"time"
)

func main() {
	var logLevel slog.LevelVar

	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: slog.NewJSONHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       &logLevel,
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

	var verbose int
	var forwardAddress string
	var serverName string
	var mode string
	var listenAddresses []string

	cmd := argp.New("dns resolver")
	cmd.AddOpt(argp.Count{I: &verbose}, "v", "verbose", "Increase verbosity, eg. -vvv")
	cmd.AddOpt(&forwardAddress, "f", "forward", "Forward address")
	cmd.AddOpt(&serverName, "s", "server", "Server name")
	cmd.AddArg(&mode, "mode", "The mode (dot or doq)")
	cmd.AddRest(&listenAddresses, "listen", "Listen address")

	if err := cmd.Parse(); err != nil {
		if errors.Is(err, argpErrors.ErrShowHelp) {
			cmd.PrintHelp()
			os.Exit(0)
		}
		logger.FatalWithExitingMessage("An error occurred when parsing the command line arguments.", err)
	}

	if verbose > 0 {
		logLevel.Set(slog.LevelDebug)
	}

	if forwardAddress == "" {
		logger.FatalWithExitingMessage("The forward address is empty.", nil)
	}

	if mode == "" {
		logger.FatalWithExitingMessage("The mode is empty.", nil)
	}
	if mode != "dot" && mode != "doq" {
		logger.FatalWithExitingMessage("Unsupported mode.", nil)
	}

	if len(listenAddresses) == 0 {
		logger.FatalWithExitingMessage("No listen addresses.", nil)
	}

	errGroup, errGroupCtx := errgroup.WithContext(context.Background())

	dnsResolver, err := resolver.New(errGroupCtx, mode, forwardAddress, serverName)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when creating the TCP resolver.",
			err,
			forwardAddress,
		)
	}
	defer func() {
		if err := dnsResolver.Close(); err != nil {
			logger.Warning(
				"An error occurred when closing the resolver.",
				motmedelErrors.New(fmt.Errorf("resolver close: %w", err), dnsResolver),
			)
		}
	}()

	go dnsResolver.Cache.StartJanitor(errGroupCtx, 5*time.Minute)

	// TODO: Add (diagnostic) HTTP server as well?

	for _, listenAddress := range listenAddresses {
		for _, transportProtocol := range []string{"udp", "tcp"} {
			errGroup.Go(
				func() error {
					server := &dns.Server{Addr: listenAddress, Net: transportProtocol, Handler: dnsResolver}
					if err := server.ListenAndServe(); err != nil {
						return motmedelErrors.NewWithTrace(
							fmt.Errorf("dns server listen and serve (%s): %w", transportProtocol, err),
							listenAddress,
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
