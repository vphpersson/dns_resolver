package resolver_config

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	t.Parallel()

	defaults := Config{
		MaxConnections:       DefaultMaxConnections,
		IdleTimeout:          DefaultIdleTimeout,
		MinIdleConnections:   DefaultMinIdleConnections,
		KeepAliveInterval:    DefaultKeepAliveInterval,
		RequestTimeout:       DefaultRequestTimeout,
		MaxInFlight:          DefaultMaxInFlight,
		MaxInFlightPerClient: DefaultMaxInFlightPerClient,
	}

	testCases := []struct {
		name    string
		options []Option
		want    func() Config
	}{
		{name: "defaults", want: func() Config { return defaults }},
		{name: "nil option", options: []Option{nil}, want: func() Config { return defaults }},
		{
			name: "every option",
			options: []Option{
				WithMaxConnections(64),
				WithIdleTimeout(time.Second),
				WithMinIdleConnections(2),
				WithKeepAliveInterval(3 * time.Second),
				WithRequestTimeout(4 * time.Second),
				WithMaxInFlight(5),
				WithMaxInFlightPerClient(9),
				WithCacheMaxEntries(6),
				WithCacheMaxBytes(7),
			},
			want: func() Config {
				return Config{
					MaxConnections:       64,
					IdleTimeout:          time.Second,
					MinIdleConnections:   2,
					KeepAliveInterval:    3 * time.Second,
					RequestTimeout:       4 * time.Second,
					MaxInFlight:          5,
					MaxInFlightPerClient: 9,
					CacheMaxEntries:      6,
					CacheMaxBytes:        7,
				}
			},
		},
		{
			name:    "later option wins",
			options: []Option{WithMaxInFlight(1), WithMaxInFlight(2)},
			want: func() Config {
				config := defaults
				config.MaxInFlight = 2
				return config
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got, want := *New(testCase.options...), testCase.want(); got != want {
				t.Fatalf("New() = %+v; want %+v", got, want)
			}
		})
	}
}
