package main

import (
	"context"
	"dns_resolver/pkg/types/abp_blocklist"
	"dns_resolver/pkg/types/hosts"
	"dns_resolver/pkg/types/resolver"
	"dns_resolver/pkg/types/resolver_config"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	motmedelDnsLog "github.com/Motmedel/dns_utils/pkg/log"
	argumentParserPkg "github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	argumentParserErrors "github.com/altshiftab/utils_go/pkg/cli/argument_parser/errors"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftErrorLogger "github.com/altshiftab/utils_go/pkg/log/error_logger"
	motmedelLogHandler "github.com/altshiftab/utils_go/pkg/log/handler"
	schemaUtils "github.com/altshiftab/utils_go/pkg/schema/utils"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// Argument validation failures, wrapped with the offending value.
var (
	errInvalidMaxConnections     = errors.New("invalid max connections")
	errInvalidMinWarmConnections = errors.New("invalid min warm connections")
	errInvalidBlocklist          = errors.New("invalid blocklist")
	errDuplicateBlocklistName    = errors.New("duplicate blocklist name")
)

const programName = "dns_resolver"

const (
	diagnosticsReadHeaderTimeout = 5 * time.Second
	diagnosticsReadTimeout       = 15 * time.Second
	diagnosticsWriteTimeout      = 30 * time.Second
	diagnosticsIdleTimeout       = 60 * time.Second
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

	logger := &altshiftErrorLogger.Logger{
		Logger: slog.New(
			&altshiftLog.ContextHandler{
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
				Extractors: []altshiftLog.ContextExtractor{
					&altshiftLog.ErrorContextExtractor{
						ContextExtractors: []altshiftLog.ContextExtractor{
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
	var infoAddress string

	// Pre-seed with the package defaults so the flags are optional; an omitted
	// flag leaves the default in place. Durations are taken as strings and
	// parsed after the fact (the argument parser has no duration option).
	maxConnections := resolver_config.DefaultMaxConnections
	minWarmConnections := resolver_config.DefaultMinIdleConnections
	idleTimeoutString := resolver_config.DefaultIdleTimeout.String()
	keepAliveIntervalString := resolver_config.DefaultKeepAliveInterval.String()

	parser := &argumentParserPkg.Parser{
		ProgramName: programName,
		Description: "Resolve DNS over an encrypted upstream, with caching, hosts and blocklists.",
		Options: []option.Option{
			option.NewStringOption('f', "forward", "forward address", true, &forwardAddress),
			option.NewBoolOption('v', "verbose", "whether verbose", false, &verbose),
			option.NewStringOption('s', "server", "server name", false, &serverName),
			option.NewStringOption('m', "mode", "mode", true, &mode),
			option.NewStringsOption('l', "listen", "listen address", true, &listenAddresses),
			option.NewStringOption('H', "hosts-file", "hosts file to consult before forwarding", false, &hostsFile),
			option.NewStringsOption('b', "blocklist", "blocklist NAME=PATH (repeatable)", false, &blocklistArgs),
			option.NewIntOption('c', "max-connections", "max concurrent upstream DoT connections (dot mode)", false, &maxConnections),
			option.NewIntOption('w', "min-warm-connections", "warm upstream DoT connections kept ready; 0 disables (dot mode)", false, &minWarmConnections),
			option.NewStringOption('i', "idle-timeout", "idle timeout for surplus pooled connections, e.g. 30s (dot mode)", false, &idleTimeoutString),
			option.NewStringOption('k', "keepalive-interval", "keep-alive ping interval for warm connections, e.g. 10s; 0 disables (dot mode)", false, &keepAliveIntervalString),
			option.NewStringOption('I', "info", "address:port for the diagnostic HTTP server (/metrics, /cache); omit to disable. Bind to loopback/LAN only", false, &infoAddress),
		},
	}

	if err := parser.Validate(); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when validating the argument parser.",
			altshiftErrors.NewWithTrace(fmt.Errorf("argument parser validate: %w", err)),
		)
	}

	if err := parser.Parse(); err != nil {
		// Help is an answer to an explicit request, not a failure.
		if errors.Is(err, argumentParserErrors.ErrHelp) {
			return
		}

		logger.FatalWithExitingMessage(
			"An error occurred when parsing the arguments.",
			altshiftErrors.NewWithTrace(fmt.Errorf("argument parser parse: %w", err)),
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

	if maxConnections < 1 {
		logger.FatalWithExitingMessage(
			"The max connections must be at least 1.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", errInvalidMaxConnections, maxConnections)),
		)
	}

	if minWarmConnections < 0 {
		logger.FatalWithExitingMessage(
			"The min warm connections cannot be negative.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", errInvalidMinWarmConnections, minWarmConnections)),
		)
	}

	idleTimeout, err := time.ParseDuration(idleTimeoutString)
	if err != nil || idleTimeout < 0 {
		logger.FatalWithExitingMessage(
			"The idle timeout is invalid.",
			altshiftErrors.NewWithTrace(fmt.Errorf("invalid idle timeout %q: %w", idleTimeoutString, err)),
		)
	}

	keepAliveInterval, err := time.ParseDuration(keepAliveIntervalString)
	if err != nil || keepAliveInterval < 0 {
		logger.FatalWithExitingMessage(
			"The keepalive interval is invalid.",
			altshiftErrors.NewWithTrace(fmt.Errorf("invalid keepalive interval %q: %w", keepAliveIntervalString, err)),
		)
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
				altshiftErrors.NewWithTrace(fmt.Errorf("%w: %q", errInvalidBlocklist, arg)),
			)
		}
		if _, dup := seenBlocklistNames[name]; dup {
			logger.FatalWithExitingMessage(
				"Duplicate blocklist name.",
				altshiftErrors.NewWithTrace(fmt.Errorf("%w: %q", errDuplicateBlocklistName, name)),
			)
		}
		seenBlocklistNames[name] = struct{}{}
		blocklistConfigs = append(blocklistConfigs, blocklistConfig{name: name, path: path})
	}

	errGroup, errGroupCtx := errgroup.WithContext(context.Background())

	dnsResolver, err := resolver.New(
		errGroupCtx,
		mode,
		forwardAddress,
		serverName,
		resolver_config.WithMaxConnections(maxConnections),
		resolver_config.WithMinIdleConnections(minWarmConnections),
		resolver_config.WithIdleTimeout(idleTimeout),
		resolver_config.WithKeepAliveInterval(keepAliveInterval),
	)
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
				altshiftErrors.New(fmt.Errorf("resolver close: %w", err), dnsResolver),
			)
		}
	}()

	for _, bc := range blocklistConfigs {
		source := abp_blocklist.New(bc.name, bc.path)

		if changed, err := source.Reload(); err != nil {
			slog.WarnContext(
				altshiftContext.WithError(
					errGroupCtx,
					altshiftErrors.New(fmt.Errorf("blocklist reload: %w", err), bc.name, bc.path),
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
				return altshiftErrors.NewWithTrace(
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
		if err := hostsResolver.Reload(errGroupCtx); err != nil {
			logger.FatalWithExitingMessage(
				"An error occurred when loading the hosts file.",
				fmt.Errorf("hosts reload: %w", err),
				hostsFile,
			)
		}
		dnsResolver.Hosts = hostsResolver

		errGroup.Go(func() error {
			if err := hostsResolver.Watch(errGroupCtx); err != nil {
				return altshiftErrors.NewWithTrace(
					fmt.Errorf("hosts watch: %w", err),
					hostsFile,
				)
			}
			return nil
		})
	}

	go dnsResolver.Cache.StartJanitor(errGroupCtx, 5*time.Minute)
	go dnsResolver.StartConnectionMaintenance(errGroupCtx)

	if infoAddress != "" {
		errGroup.Go(func() error {
			server := &http.Server{
				Addr:    infoAddress,
				Handler: dnsResolver.DiagnosticsHandler(),
				// A client must not be able to hold the diagnostics server open
				// by trickling a request at it.
				ReadHeaderTimeout: diagnosticsReadHeaderTimeout,
				ReadTimeout:       diagnosticsReadTimeout,
				WriteTimeout:      diagnosticsWriteTimeout,
				IdleTimeout:       diagnosticsIdleTimeout,
			}
			// Shut the diagnostic server down when the group context ends so it
			// does not keep the process alive after the DNS servers exit.
			context.AfterFunc(errGroupCtx, func() { _ = server.Close() })
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return altshiftErrors.NewWithTrace(
					fmt.Errorf("diagnostics http server listen and serve: %w", err),
					infoAddress,
				)
			}
			return nil
		})
	}

	for _, listenAddress := range listenAddresses {
		for _, transportProtocol := range []string{"udp", "tcp"} {
			errGroup.Go(
				func() error {
					server := &dns.Server{Addr: listenAddress, Net: transportProtocol, Handler: dnsResolver}
					if err := server.ListenAndServe(); err != nil {
						return altshiftErrors.NewWithTrace(
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
