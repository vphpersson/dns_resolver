package main

import (
	"bytes"
	"context"
	"dns_resolver/pkg/types/abp_blocklist"
	"dns_resolver/pkg/types/resolver"
	"fmt"
	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/http/errors"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	"github.com/miekg/dns"
	"github.com/vphpersson/argument_parser/pkg/argument_parser"
	"github.com/vphpersson/argument_parser/pkg/types/option"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

func getOisdBigList() (*abp_blocklist.List, error) {
	response, body, err := motmedelHttpUtils.Fetch(
		context.Background(),
		"https://big.oisd.nl",
		&http.Client{Timeout: 10 * time.Second},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}

	responseHeader := response.Header
	if responseHeader == nil {
		return nil, motmedelErrors.NewWithTrace(errors.ErrNilHttpResponseHeader)
	}

	list, err := abp_blocklist.FromReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("abp blocklist from reader: %w", err)
	}
	if list == nil {
		return nil, motmedelErrors.NewWithTrace(abp_blocklist.ErrNilList)
	}

	etag := responseHeader.Get("ETag")
	unquotedEtag, err := strconv.Unquote(etag)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("strconv unquote: %w", err), etag)
	}

	list.Rule = &ecs.Rule{
		Id: unquotedEtag,
		Name: "oisd big",
		Version: responseHeader.Get("Last-Modified"),
	}

	return list, nil
}

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
					&motmedelLog.ErrorContextExtractor{
						ContextExtractors: []motmedelLog.ContextExtractor{
							&motmedelDnsLog.DnsContextExtractor,
						},
					},
					&motmedelDnsLog.DnsContextExtractor,
				},
			},
		).With(slog.Group("event", slog.String("dataset", "dns_resolver"))),
	}
	slog.SetDefault(logger.Logger)

	var verbose bool
	var forwardAddress string
	var serverName string
	var mode string
	var listenAddresses []string

	argumentParser := argument_parser.ArgumentParser{
		Options: []option.Option{
			option.NewStringOption('f', "forward", "forward address", true, &forwardAddress),
			option.NewBoolOption('v', "verbose", "whether verbose", false, &verbose),
			option.NewStringOption('s', "server", "server name", false, &serverName),
			option.NewStringOption('m', "mode", "mode", true, &mode),
			option.NewStringsOption('l', "listen", "listen address", true, &listenAddresses),
		},
	}

	if err := argumentParser.Parse(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when parsing the arguments.",
			motmedelErrors.NewWithTrace(fmt.Errorf("argument parser parse: %w", err)),
		)
	}

	if verbose {
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

	oisdBigList, err := getOisdBigList()
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when getting the oisd big list.",
			fmt.Errorf("get oisd big list: %w", err),
		)
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

	dnsResolver.Blocklists = []resolver.Blocklist{oisdBigList}

	go dnsResolver.Cache.StartJanitor(errGroupCtx, 5*time.Minute)

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-errGroupCtx.Done():
				return
			case <-ticker.C:
				select {
				case <-errGroupCtx.Done():
					return
				default:
					refreshList, err := getOisdBigList()
					if err != nil {
						slog.ErrorContext(
							motmedelContext.WithErrorContextValue(
								errGroupCtx,
								fmt.Errorf("get oisd big list: %w", err),
							),
							"An error occurred when getting the oisd big list.",
						)
					}

					dnsResolver.Blocklists = []resolver.Blocklist{refreshList}
				}
			}
		}
	}()

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
