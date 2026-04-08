package main

import (
	"context"
	"dns_resolver/pkg/types/abp_blocklist"
	"dns_resolver/pkg/types/hosts"
	"dns_resolver/pkg/types/resolver"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelErrorLogger "github.com/Motmedel/utils_go/pkg/log/error_logger"
	motmedelLogHandler "github.com/Motmedel/utils_go/pkg/log/handler"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/miekg/dns"
	"github.com/vphpersson/argument_parser/pkg/argument_parser"
	"github.com/vphpersson/argument_parser/pkg/types/option"
	"golang.org/x/sync/errgroup"
)

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
	var hostsFile string
	var blocklistArgs []string

	argumentParser := argument_parser.Parser{
		Options: []option.Option{
			option.NewStringOption('f', "forward", "forward address", true, &forwardAddress),
			option.NewBoolOption('v', "verbose", "whether verbose", false, &verbose),
			option.NewStringOption('s', "server", "server name", false, &serverName),
			option.NewStringOption('m', "mode", "mode", true, &mode),
			option.NewStringsOption('l', "listen", "listen address", true, &listenAddresses),
			option.NewStringOption('H', "hosts-file", "hosts file to consult before forwarding", false, &hostsFile),
			option.NewStringsOption('b', "blocklist", "blocklist NAME=PATH (repeatable)", false, &blocklistArgs),
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

	type blocklistConfig struct {
		name string
		path string
	}

	var blocklistConfigs []blocklistConfig
	seenBlocklistNames := map[string]struct{}{}
	for _, arg := range blocklistArgs {
		name, path, ok := strings.Cut(arg, "=")
		name = strings.TrimSpace(name)
		path = strings.TrimSpace(path)
		if !ok || name == "" || path == "" {
			logger.FatalWithExitingMessage(
				"Malformed blocklist argument; expected NAME=PATH.",
				motmedelErrors.NewWithTrace(fmt.Errorf("invalid blocklist: %q", arg)),
			)
		}
		if _, dup := seenBlocklistNames[name]; dup {
			logger.FatalWithExitingMessage(
				"Duplicate blocklist name.",
				motmedelErrors.NewWithTrace(fmt.Errorf("duplicate blocklist name: %q", name)),
			)
		}
		seenBlocklistNames[name] = struct{}{}
		blocklistConfigs = append(blocklistConfigs, blocklistConfig{name: name, path: path})
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

	for _, bc := range blocklistConfigs {
		source := abp_blocklist.New(bc.name, bc.path)

		if changed, err := source.Reload(); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(
					errGroupCtx,
					motmedelErrors.New(fmt.Errorf("blocklist reload: %w", err), bc.name, bc.path),
				),
				"",
				slog.Group(
					"event",
					slog.String("action", "blocklist_load"),
					slog.String("reason", "An error occurred when loading a blocklist; the resolver will pick the file up if it appears later."),
					slog.String("kind", "event"),
					slog.String("outcome", "failure"),
					slog.Any("category", []string{"file"}),
					slog.Any("type", []string{"error"}),
				),
			)
		} else if changed {
			var version string
			if list := source.Snapshot(); list != nil && list.Rule != nil {
				version = list.Rule.Version
			}
			slog.InfoContext(
				errGroupCtx,
				"",
				slog.Group(
					"event",
					slog.String("action", "blocklist_loaded"),
					slog.String("reason", "A blocklist was loaded."),
					slog.String("kind", "event"),
					slog.String("outcome", "success"),
					slog.Any("category", []string{"file"}),
					slog.Any("type", []string{"creation"}),
				),
				slog.Group(
					"blocklist",
					slog.String("name", bc.name),
					slog.String("path", bc.path),
					slog.String("version", version),
				),
			)
		}

		dnsResolver.SetBlocklist(bc.name, source)

		errGroup.Go(func() error {
			if err := source.Watch(errGroupCtx); err != nil {
				return motmedelErrors.NewWithTrace(
					fmt.Errorf("blocklist watch: %w", err),
					bc.name,
					bc.path,
				)
			}
			return nil
		})
	}

	if hostsFile != "" {
		hostsResolver := hosts.New(hostsFile, 0)
		if err := hostsResolver.Reload(); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when loading the hosts file.",
				fmt.Errorf("hosts reload: %w", err),
				hostsFile,
			)
		}
		dnsResolver.Hosts = hostsResolver

		errGroup.Go(func() error {
			if err := hostsResolver.Watch(errGroupCtx); err != nil {
				return motmedelErrors.NewWithTrace(
					fmt.Errorf("hosts watch: %w", err),
					hostsFile,
				)
			}
			return nil
		})
	}

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
