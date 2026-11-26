package main

import (
	"context"
	"dns_resolver/pkg/free_bind"
	"dns_resolver/pkg/types/abp_blocklist"
	"dns_resolver/pkg/types/cache"
	"dns_resolver/pkg/types/hosts"
	"dns_resolver/pkg/types/resolver"
	"dns_resolver/pkg/types/resolver_config"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	motmedelDnsLog "github.com/altshiftab/dns_utils/pkg/log"
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
	"golang.org/x/net/netutil"
	"golang.org/x/sync/errgroup"
)

// Argument validation failures, wrapped with the offending value.
var (
	errInvalidMaxConnections     = errors.New("invalid max connections")
	errInvalidMinWarmConnections = errors.New("invalid min warm connections")
	errInvalidMaxInFlight        = errors.New("invalid max in flight")
	errInvalidMaxTcpConnections  = errors.New("invalid max tcp connections")
	errInvalidCacheBound         = errors.New("invalid cache bound")
	errInvalidBlocklist          = errors.New("invalid blocklist")
	errDuplicateBlocklistName    = errors.New("duplicate blocklist name")
	errNegativeDuration          = errors.New("negative duration")
	errNonPositiveDuration       = errors.New("non-positive duration")
)

// errUnsupportedNetwork is a transport newDnsServer cannot serve.
var errUnsupportedNetwork = errors.New("unsupported network")

// listenConfig opens every listener with free binding, so an address whose
// interface is not up yet binds rather than failing the start.
var listenConfig = net.ListenConfig{Control: free_bind.Control}

// newDnsServer makes a DNS server for one address and transport ("udp" or
// "tcp"), on a socket of its own that is closed when ctx ends, which is what
// makes serve return. TCP connections are served at most maxTcpConnections at a
// time, as each holds a goroutine and a descriptor for as long as its client
// keeps it open; the descriptors are the ones the upstream dials need too.
func newDnsServer(ctx context.Context, address string, network string, handler dns.Handler, maxTcpConnections int) (*dns.Server, error) {
	server := &dns.Server{
		Addr:          address,
		Net:           network,
		Handler:       handler,
		ReadTimeout:   dnsReadTimeout,
		IdleTimeout:   func() time.Duration { return dnsTcpIdleTimeout },
		MaxTCPQueries: dnsMaxTcpQueries,
	}

	var socket io.Closer
	switch network {
	case "udp":
		packetConn, err := listenConfig.ListenPacket(ctx, "udp", address)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("listen config listen packet: %w", err), address)
		}
		server.PacketConn = packetConn
		socket = packetConn
	case "tcp":
		listener, err := listenConfig.Listen(ctx, "tcp", address)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("listen config listen: %w", err), address)
		}
		server.Listener = &writeDeadlineListener{
			Listener: netutil.LimitListener(listener, maxTcpConnections),
			timeout:  dnsWriteTimeout,
		}
		socket = server.Listener
	default:
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", errUnsupportedNetwork, network), address)
	}

	context.AfterFunc(ctx, func() {
		// Shutdown also ends the connections already accepted, which closing the
		// listening socket alone leaves to their clients: an open TCP connection
		// would hold the exit for its idle timeout, or for as long as its client
		// keeps querying. Closing the socket covers a server not started yet,
		// which Shutdown refuses.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dnsShutdownTimeout)
		defer cancel()
		_ = server.ShutdownContext(shutdownCtx)
		_ = socket.Close()
	})

	return server, nil
}

// writeDeadlineListener gives each write on a connection it accepts a deadline,
// and closes a connection whose write fails. miekg/dns takes a WriteTimeout but
// never applies it, so a client that sends queries and reads none of the answers
// would block a write once its window filled, and hold the connection, and with
// it a slot of the TCP limit, for good: read and idle timeouts do not end a
// write. A write that failed has left the stream mid-message, so the connection
// is closed, which ends its queries and frees its slot.
type writeDeadlineListener struct {
	net.Listener
	timeout time.Duration
}

func (listener *writeDeadlineListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &writeDeadlineConn{Conn: conn, timeout: listener.timeout}, nil
}

type writeDeadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (conn *writeDeadlineConn) Write(data []byte) (int, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(conn.timeout)); err != nil {
		_ = conn.Close()
		return 0, err
	}

	written, err := conn.Conn.Write(data)
	if err != nil {
		_ = conn.Close()
	}

	return written, err
}

// serve runs server on the socket newDnsServer opened for it, until the socket
// fails or is closed.
func serve(server *dns.Server) error {
	if err := server.ActivateAndServe(); err != nil {
		return fmt.Errorf("dns server activate and serve: %w", err)
	}
	return nil
}

// serveDns serves handler on every address over UDP and TCP until ctx ends or
// one of the servers fails. A failure closes every other server's socket and is
// returned, so the process exits and its supervisor starts it again: the servers
// left running would otherwise go on answering with a handler whose context had
// ended, which is to say with SERVFAIL, and nothing would restart them.
func serveDns(ctx context.Context, addresses []string, handler dns.Handler, maxTcpConnections int) error {
	group, groupCtx := errgroup.WithContext(ctx)
	for _, address := range addresses {
		for _, network := range []string{"udp", "tcp"} {
			group.Go(func() error {
				server, err := newDnsServer(groupCtx, address, network, handler, maxTcpConnections)
				if err != nil {
					return altshiftErrors.New(fmt.Errorf("new dns server (%s): %w", network, err), address)
				}
				// Once the group's context has ended, the socket was closed on
				// purpose, and whatever ended it is the error worth reporting.
				if err := serve(server); err != nil && groupCtx.Err() == nil {
					return altshiftErrors.NewWithTrace(fmt.Errorf("serve (%s): %w", network, err), address)
				}
				return nil
			})
		}
	}

	if err := group.Wait(); err != nil {
		return fmt.Errorf("errgroup wait: %w", err)
	}

	return nil
}

// interfaceAddresses is an interface's name and index, which a zone names, and
// the addresses it has.
type interfaceAddresses struct {
	name      string
	index     int
	addresses []netip.Addr
}

// collectInterfaceAddresses returns every interface with its addresses.
func collectInterfaceAddresses() ([]*interfaceAddresses, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("net interfaces: %w", err))
	}

	collected := make([]*interfaceAddresses, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		addrs, err := networkInterface.Addrs()
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("interface addrs: %w", err), networkInterface.Name)
		}

		entry := &interfaceAddresses{name: networkInterface.Name, index: networkInterface.Index}
		for _, addr := range addrs {
			var ip net.IP
			switch typed := addr.(type) {
			case *net.IPNet:
				ip = typed.IP
			case *net.IPAddr:
				ip = typed.IP
			}
			if address, ok := netip.AddrFromSlice(ip); ok {
				entry.addresses = append(entry.addresses, address.Unmap())
			}
		}
		collected = append(collected, entry)
	}

	return collected, nil
}

// unassignedAddresses returns the listen addresses whose host is an address no
// interface has, or none of those its zone names: free binding binds them all
// the same, so without a word they would look like listeners while receiving
// nothing until the interface comes up, or ever, for a mistyped one. A wildcard
// host, or one that is not an address, is not reported.
func unassignedAddresses(listenAddresses []string, interfaces []*interfaceAddresses) []string {
	var unassigned []string
	for _, listenAddress := range listenAddresses {
		host, _, err := net.SplitHostPort(listenAddress)
		if err != nil {
			continue
		}
		address, err := netip.ParseAddr(host)
		if err != nil || address.IsUnspecified() {
			continue
		}
		zone := address.Zone()
		address = address.WithZone("").Unmap()

		assigned := false
		for _, networkInterface := range interfaces {
			if networkInterface == nil {
				continue
			}
			if zone != "" && zone != networkInterface.name && zone != strconv.Itoa(networkInterface.index) {
				continue
			}
			if slices.Contains(networkInterface.addresses, address) {
				assigned = true
				break
			}
		}
		if !assigned {
			unassigned = append(unassigned, listenAddress)
		}
	}
	return unassigned
}

// parseDuration parses a duration flag value. A negative value is refused, and
// so is zero unless allowZero is set.
func parseDuration(value string, allowZero bool) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("time parse duration: %w", err)
	}
	if duration < 0 {
		return 0, fmt.Errorf("%w: %s", errNegativeDuration, value)
	}
	if duration == 0 && !allowZero {
		return 0, fmt.Errorf("%w: %s", errNonPositiveDuration, value)
	}
	return duration, nil
}

const programName = "dns_resolver"

const (
	// The defaults miekg/dns would apply anyway, stated so they are this
	// program's: the time a TCP client has to send its first query, then
	// between queries, and the queries one connection may carry. The time an
	// answer has to be written is applied by writeDeadlineListener, as miekg/dns
	// applies none.
	dnsReadTimeout    = 2 * time.Second
	dnsWriteTimeout   = 2 * time.Second
	dnsTcpIdleTimeout = 8 * time.Second
	dnsMaxTcpQueries  = 128
	// dnsShutdownTimeout bounds the wait for a server's queries in progress
	// when it is shut down.
	dnsShutdownTimeout = 5 * time.Second
	// defaultMaxTcpConnections bounds the TCP connections served at once. A
	// connection over the bound waits in the listen backlog for a free one.
	defaultMaxTcpConnections = 128
)

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
	requestTimeoutString := resolver_config.DefaultRequestTimeout.String()
	maxInFlight := resolver_config.DefaultMaxInFlight
	maxInFlightPerClient := resolver_config.DefaultMaxInFlightPerClient
	maxTcpConnections := defaultMaxTcpConnections
	cacheMaxEntries := cache.DefaultMaxEntries
	cacheMaxBytes := cache.DefaultMaxBytes

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
			option.NewStringsOption('b', "blocklist", "ABP-format blocklist NAME=PATH (repeatable); an @@ allow rule in any list overrides block rules in all of them, $important ones included", false, &blocklistArgs),
			option.NewIntOption('c', "max-connections", "max concurrent upstream DoT connections (dot mode)", false, &maxConnections),
			option.NewIntOption('w', "min-warm-connections", "warm upstream DoT connections kept ready; 0 disables (dot mode)", false, &minWarmConnections),
			option.NewStringOption('i', "idle-timeout", "idle timeout for surplus pooled connections, e.g. 30s (dot mode)", false, &idleTimeoutString),
			option.NewStringOption('k', "keepalive-interval", "keep-alive ping interval for warm connections, e.g. 10s; 0 disables (dot mode)", false, &keepAliveIntervalString),
			option.NewStringOption('t', "request-timeout", "time allowed to answer one request, upstream attempts included, e.g. 4s", false, &requestTimeoutString),
			option.NewIntOption(0, "max-in-flight", "requests that may wait on the upstream at once; beyond it a request is answered SERVFAIL", false, &maxInFlight),
			option.NewIntOption(0, "max-in-flight-per-client", "requests one client may have waiting on the upstream at once, beyond which its requests are answered SERVFAIL; 0, the default, bounds nothing", false, &maxInFlightPerClient),
			option.NewIntOption(0, "max-tcp-connections", "TCP client connections served at once", false, &maxTcpConnections),
			option.NewIntOption(0, "cache-max-entries", "answers the cache holds at most; the least recently used go first", false, &cacheMaxEntries),
			option.NewIntOption(0, "cache-max-bytes", "approximate memory the cached answers take at most, in bytes", false, &cacheMaxBytes),
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
		// Help and a completion script are answers to an explicit request, not
		// failures; both have already been written to stdout.
		if errors.Is(err, argumentParserErrors.ErrHelp) || errors.Is(err, argumentParserErrors.ErrCompletion) {
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

	if maxInFlight < 1 {
		logger.FatalWithExitingMessage(
			"The max in flight must be at least 1.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", errInvalidMaxInFlight, maxInFlight)),
		)
	}

	if maxInFlightPerClient < 0 {
		logger.FatalWithExitingMessage(
			"The max in flight per client must not be negative.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", errInvalidMaxInFlight, maxInFlightPerClient)),
		)
	}

	if maxTcpConnections < 1 {
		logger.FatalWithExitingMessage(
			"The max TCP connections must be at least 1.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", errInvalidMaxTcpConnections, maxTcpConnections)),
		)
	}

	if cacheMaxEntries < 1 || cacheMaxBytes < 1 {
		logger.FatalWithExitingMessage(
			"The cache bounds must be at least 1.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d entries, %d bytes", errInvalidCacheBound, cacheMaxEntries, cacheMaxBytes)),
		)
	}

	if minWarmConnections < 0 {
		logger.FatalWithExitingMessage(
			"The min warm connections cannot be negative.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d", errInvalidMinWarmConnections, minWarmConnections)),
		)
	}

	idleTimeout, err := parseDuration(idleTimeoutString, true)
	if err != nil {
		logger.FatalWithExitingMessage(
			"The idle timeout is invalid.",
			altshiftErrors.NewWithTrace(fmt.Errorf("parse duration (idle timeout): %w", err), idleTimeoutString),
		)
	}

	keepAliveInterval, err := parseDuration(keepAliveIntervalString, true)
	if err != nil {
		logger.FatalWithExitingMessage(
			"The keepalive interval is invalid.",
			altshiftErrors.NewWithTrace(fmt.Errorf("parse duration (keepalive interval): %w", err), keepAliveIntervalString),
		)
	}

	requestTimeout, err := parseDuration(requestTimeoutString, false)
	if err != nil {
		logger.FatalWithExitingMessage(
			"The request timeout is invalid.",
			altshiftErrors.NewWithTrace(fmt.Errorf("parse duration (request timeout): %w", err), requestTimeoutString),
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
		resolver_config.WithRequestTimeout(requestTimeout),
		resolver_config.WithMaxInFlight(maxInFlight),
		resolver_config.WithMaxInFlightPerClient(maxInFlightPerClient),
		resolver_config.WithCacheMaxEntries(cacheMaxEntries),
		resolver_config.WithCacheMaxBytes(cacheMaxBytes),
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
			// Bound as the DNS servers are, so an address whose interface is not
			// up yet does not fail the start.
			listener, err := listenConfig.Listen(errGroupCtx, "tcp", infoAddress)
			if err != nil {
				return altshiftErrors.NewWithTrace(fmt.Errorf("listen config listen: %w", err), infoAddress)
			}
			// Shut the diagnostic server down when the group context ends so it
			// does not keep the process alive after the DNS servers exit.
			context.AfterFunc(errGroupCtx, func() { _ = server.Close() })
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return altshiftErrors.NewWithTrace(
					fmt.Errorf("diagnostics http server serve: %w", err),
					infoAddress,
				)
			}
			return nil
		})
	}

	boundAddresses := listenAddresses
	if infoAddress != "" {
		boundAddresses = append(slices.Clone(listenAddresses), infoAddress)
	}
	if interfaces, err := collectInterfaceAddresses(); err != nil {
		slog.WarnContext(
			altshiftContext.WithError(errGroupCtx, err),
			"",
			slog.Group(
				"event",
				slog.String("action", "listen"),
				slog.String("reason", "The interfaces' addresses could not be listed, so an address listened on that no interface has goes unreported."),
				slog.String("kind", "event"),
				slog.String("outcome", "failure"),
				slog.Any("category", []string{"network"}),
				slog.Any("type", []string{"error"}),
			),
		)
	} else {
		for _, boundAddress := range unassignedAddresses(boundAddresses, interfaces) {
			slog.WarnContext(
				errGroupCtx,
				"",
				slog.Group(
					"event",
					slog.String("action", "listen"),
					slog.String("reason", "No interface has the address listened on yet; it is served once one does."),
					slog.String("kind", "event"),
					slog.String("outcome", "unknown"),
					slog.Any("category", []string{"network"}),
					slog.Any("type", []string{"start"}),
				),
				slog.Group("server", slog.String("address", boundAddress)),
			)
		}
	}

	errGroup.Go(func() error {
		if err := serveDns(errGroupCtx, listenAddresses, dnsResolver, maxTcpConnections); err != nil {
			return fmt.Errorf("serve dns: %w", err)
		}
		return nil
	})

	if err := errGroup.Wait(); err != nil {
		logger.FatalWithExitingMessage("A server error occurred.", err)
	}
}
