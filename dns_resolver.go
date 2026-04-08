package main

import (
	"bytes"
	"context"
	"dns_resolver/pkg/types/abp_blocklist"
	"dns_resolver/pkg/types/resolver"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/errors"
	"github.com/Motmedel/utils_go/pkg/http/types/fetch_config"
	motmedelHttpUtils "github.com/Motmedel/utils_go/pkg/http/utils"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	motmedelLogHandler "github.com/Motmedel/utils_go/pkg/log/handler"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/miekg/dns"
	"github.com/vphpersson/argument_parser/pkg/argument_parser"
	"github.com/vphpersson/argument_parser/pkg/types/option"
	"golang.org/x/sync/errgroup"
)

// getOisdBigList fetches the OISD big blocklist. If etag or lastModified are
// non-empty, a conditional request is made; on a 304 Not Modified response
// this returns (nil, nil) to signal the caller that the current list is still
// up to date.
func getOisdBigList(etag string, lastModified string) (*abp_blocklist.List, error) {
	headers := map[string]string{}
	if etag != "" {
		headers["If-None-Match"] = `"` + etag + `"`
	}
	if lastModified != "" {
		headers["If-Modified-Since"] = lastModified
	}

	response, body, err := motmedelHttpUtils.Fetch(
		context.Background(),
		"https://big.oisd.nl",
		fetch_config.WithHttpClient(&http.Client{Timeout: 10 * time.Second}),
		fetch_config.WithHeaders(headers),
		fetch_config.WithSkipErrorOnStatus(true),
	)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	if response == nil {
		return nil, motmedelErrors.NewWithTrace(errors.ErrNilHttpResponse)
	}

	if response.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("unexpected status code: %d", response.StatusCode),
		)
	}

	list, err := abp_blocklist.FromReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("abp blocklist from reader: %w", err)
	}
	if list == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("list"))
	}

	newEtag := response.Header.Get("ETag")
	unquotedEtag, err := strconv.Unquote(newEtag)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("strconv unquote: %w", err), newEtag)
	}

	list.Rule = &schema.Rule{
		Id:      unquotedEtag,
		Name:    "oisd big",
		Version: response.Header.Get("Last-Modified"),
	}

	return list, nil
}

func main() {
	var logLevel slog.LevelVar

	replaceAttr := func(groups []string, attr slog.Attr) slog.Attr {
		attr = schemaUtils.TimestampReplaceAttr(groups, attr)
		// Drop the top-level `message` attribute when it is empty so that log
		// sites that intentionally leave it to be populated later (e.g. by
		// the DNS context extractor) do not emit a dangling empty field.
		if len(groups) == 0 && attr.Key == "message" {
			if value, ok := attr.Value.Any().(string); ok && value == "" {
				return slog.Attr{}
			}
		}
		return attr
	}

	logger := &motmedelErrorLogger.Logger{
		Logger: slog.New(
			&motmedelLog.ContextHandler{
				Next: motmedelLogHandler.New(
					slog.NewJSONHandler(
						os.Stdout,
						&slog.HandlerOptions{
							AddSource:   false,
							Level:       &logLevel,
							ReplaceAttr: replaceAttr,
						},
					),
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

	argumentParser := argument_parser.Parser{
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

	oisdBigList, err := getOisdBigList("", "")
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when getting the oisd big list.",
			fmt.Errorf("get oisd big list: %w", err),
		)
	}
	if oisdBigList == nil {
		logger.FatalWithExitingMessage("The initial oisd big list is empty.", nil)
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

	dnsResolver.SetBlocklists([]resolver.Blocklist{oisdBigList})

	go dnsResolver.Cache.StartJanitor(errGroupCtx, 5*time.Minute)

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		currentList := oisdBigList
		for {
			select {
			case <-errGroupCtx.Done():
				return
			case <-ticker.C:
				select {
				case <-errGroupCtx.Done():
					return
				default:
					var etag, lastModified string
					if rule := currentList.Rule; rule != nil {
						etag = rule.Id
						lastModified = rule.Version
					}

					refreshList, err := getOisdBigList(etag, lastModified)
					if err != nil {
						slog.ErrorContext(
							motmedelContext.WithError(
								errGroupCtx,
								fmt.Errorf("get oisd big list: %w", err),
							),
							"",
							slog.Group(
								"event",
								slog.String("action", "blocklist_refresh"),
								slog.String("reason", "An error occurred when getting the oisd big list."),
								slog.String("kind", "event"),
								slog.String("outcome", "failure"),
								slog.Any("category", []string{"network"}),
								slog.Any("type", []string{"error"}),
							),
						)
						continue
					}
					if refreshList == nil {
						// 304 Not Modified — keep the current list.
						continue
					}

					currentList = refreshList
					dnsResolver.SetBlocklists([]resolver.Blocklist{refreshList})
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
