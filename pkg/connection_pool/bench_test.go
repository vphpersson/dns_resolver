package connection_pool_test

import (
	"context"
	"testing"

	"dns_resolver/pkg/connection_pool"
)

type benchConn struct{}

func (benchConn) Close() error { return nil }

func BenchmarkGetPut(b *testing.B) {
	pool := connection_pool.New[benchConn](func() (benchConn, error) { return benchConn{}, nil })
	pool.MaxNumConnections = 8
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		connection, err := pool.Get(ctx)
		if err != nil {
			b.Fatal(err)
		}
		pool.Put(ctx, connection, nil)
	}
}
