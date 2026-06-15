package resolver_config

import "time"

const (
	// DefaultMaxConnections is the default upper bound on the number of
	// concurrent upstream DoT connections held by the connection pool.
	DefaultMaxConnections = 5
	// DefaultIdleTimeout is how long a surplus (non-warm) pooled connection may
	// sit idle before it is discarded. It must stay below the upstream's own
	// idle-close window, otherwise the pool hands out connections the server has
	// already closed, and the exchange fails (EOF, or a full read-timeout when
	// the teardown is a silent drop). Mullvad's DoT endpoint closes idle
	// connections at ~10s, so 5s keeps a safe margin.
	DefaultIdleTimeout = 5 * time.Second
	// DefaultMinIdleConnections is the number of warm connections kept ready so
	// the common cache-miss query reuses an existing connection rather than
	// paying a fresh TCP+TLS handshake. 0 disables warm-keeping.
	DefaultMinIdleConnections = 1
	// DefaultKeepAliveInterval is how often warm connections are pinged to keep
	// them alive against the upstream's idle close; it must be shorter than that
	// idle window to be effective. At 10s it raced Mullvad's ~10s close, so 5s.
	// 0 disables pool maintenance entirely.
	DefaultKeepAliveInterval = 5 * time.Second
)

// Config holds tunable resolver settings. It is assembled from a set of
// Options rather than constructed directly by callers.
type Config struct {
	// MaxConnections bounds the number of concurrent upstream DoT connections.
	// A value <= 0 leaves the connection pool's own default in place. It has no
	// effect in "doq" mode, which does not use a connection pool.
	MaxConnections int
	// IdleTimeout discards surplus pooled connections idle longer than this.
	IdleTimeout time.Duration
	// MinIdleConnections is the number of warm DoT connections kept ready.
	MinIdleConnections int
	// KeepAliveInterval is how often the pool's maintenance loop runs to ping
	// the warm set and replenish it.
	KeepAliveInterval time.Duration
}

// Option mutates a Config.
type Option func(*Config)

// WithMaxConnections sets the maximum number of concurrent upstream DoT
// connections.
func WithMaxConnections(maxConnections int) Option {
	return func(config *Config) {
		config.MaxConnections = maxConnections
	}
}

// WithIdleTimeout sets how long a surplus pooled connection may sit idle before
// it is discarded.
func WithIdleTimeout(idleTimeout time.Duration) Option {
	return func(config *Config) {
		config.IdleTimeout = idleTimeout
	}
}

// WithMinIdleConnections sets the number of warm DoT connections kept ready.
func WithMinIdleConnections(minIdleConnections int) Option {
	return func(config *Config) {
		config.MinIdleConnections = minIdleConnections
	}
}

// WithKeepAliveInterval sets how often the connection pool's maintenance loop
// runs.
func WithKeepAliveInterval(keepAliveInterval time.Duration) Option {
	return func(config *Config) {
		config.KeepAliveInterval = keepAliveInterval
	}
}

// New returns a Config populated with defaults, with the given Options applied
// in order.
func New(options ...Option) *Config {
	config := &Config{
		MaxConnections:     DefaultMaxConnections,
		IdleTimeout:        DefaultIdleTimeout,
		MinIdleConnections: DefaultMinIdleConnections,
		KeepAliveInterval:  DefaultKeepAliveInterval,
	}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}
	return config
}
