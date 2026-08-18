package connection_pool_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"dns_resolver/pkg/connection_pool"
	dnsResolverErrors "dns_resolver/pkg/errors"
)

var (
	errConnectionAlreadyClosed  = errors.New("connection already closed")
	errMock                     = errors.New("mock error")
	errConnectionCreationFailed = errors.New("connection creation failed")
	errDeadConnection           = errors.New("dead connection")
)

type mockConnection struct {
	isClosed bool
	mu       sync.Mutex
}

func (mc *mockConnection) Read(_ []byte) (int, error)  { return 0, nil }
func (mc *mockConnection) Write(_ []byte) (int, error) { return 0, nil }
func (mc *mockConnection) Close() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.isClosed {
		return errConnectionAlreadyClosed
	}
	mc.isClosed = true
	return nil
}
func (mc *mockConnection) LocalAddr() net.Addr                { return nil }
func (mc *mockConnection) RemoteAddr() net.Addr               { return nil }
func (mc *mockConnection) SetDeadline(_ time.Time) error      { return nil }
func (mc *mockConnection) SetReadDeadline(_ time.Time) error  { return nil }
func (mc *mockConnection) SetWriteDeadline(_ time.Time) error { return nil }

func newMockConnection() (*mockConnection, error) {
	return &mockConnection{}, nil
}

func TestConnectionPool_New(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})

	if pool == nil {
		t.Fatal("expected pool to be initialized, got nil")
	}

	if pool.MaxNumConnections != 5 {
		t.Fatalf("expected MaxNumConnections to be 5, got %d", pool.MaxNumConnections)
	}
}

func TestConnectionPool_GetPut(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})

	// Get a connection from the pool
	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if conn == nil {
		t.Fatal("expected a valid connection, got nil")
	}

	// Put the connection back into the pool without an error
	pool.Put(t.Context(), conn, nil)

	if pool.Len() != 1 {
		t.Fatalf("expected pool length to be 1, got %d", pool.Len())
	}
}

func TestConnectionPool_MaxConnections(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.MaxNumConnections = 2

	// Get the first connection
	conn1, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn1 == nil {
		t.Fatal("expected a valid connection, got nil")
	}

	// Get the second connection
	conn2, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn2 == nil {
		t.Fatal("expected a valid connection, got nil")
	}

	// Attempt to get a third connection (should block or not succeed immediately)
	done := make(chan struct{})
	go func() {
		_, _ = pool.Get(t.Context()) // Will block
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("Expected to block on third connection request")
	case <-time.After(100 * time.Millisecond):
		// Blocked due to max connections (expected behavior)
	}

	pool.Put(t.Context(), conn1, nil)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Blocked get did not succeed after freeing up a connection")
	}
}

func TestConnectionPool_Close(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pool.Put(t.Context(), conn, nil)

	if err = pool.Close(); err != nil {
		t.Fatalf("unexpected error during pool close: %v", err)
	}

	if pool.Len() != 0 {
		t.Fatalf("expected pool to be empty after close, but got length %d", pool.Len())
	}
}

func TestConnectionPool_ErrorOnPut(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pool.Put(t.Context(), conn, errMock)

	// Verify the connection is not added back to the pool
	if pool.Len() != 0 {
		t.Fatalf("expected pool length to be 0 after error, but got %d", pool.Len())
	}
}

func TestConnectionPool_Get_MakeConnectionFails(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return nil, errConnectionCreationFailed
	})

	conn, err := pool.Get(t.Context())
	if err == nil {
		t.Fatal("expected error when MakeConnection fails, got nil")
	}
	if conn != nil {
		t.Fatal("expected nil connection when MakeConnection fails")
	}
}

func TestConnectionPool_CloseEmptyPool(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})

	// Close without any connections should not return an error
	err := pool.Close()
	if err != nil {
		t.Fatalf("expected no error closing empty pool, got %v", err)
	}
}

func TestConnectionPool_GetAfterClose(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})

	if err := pool.Close(); err != nil {
		t.Fatalf("unexpected error closing pool: %v", err)
	}

	_, err := pool.Get(t.Context())
	if !errors.Is(err, dnsResolverErrors.ErrClosedPool) {
		t.Fatalf("expected ErrClosedPool, got %v", err)
	}
}

// Regression test for Close() incorrectly resetting numActiveConnections to
// zero: if a connection was checked out during Close, later returning it and
// grabbing more must still respect MaxNumConnections.
func TestConnectionPool_CloseWithCheckedOutConnection(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.MaxNumConnections = 2

	// Check out both slots.
	conn1, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn2, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Return one so there is an idle connection when Close runs.
	pool.Put(t.Context(), conn1, nil)

	if err := pool.Close(); err != nil {
		t.Fatalf("unexpected error closing pool: %v", err)
	}

	// Returning the still-checked-out conn to a closed pool must close it,
	// not re-pool it.
	pool.Put(t.Context(), conn2, nil)
	if !conn2.isClosed {
		t.Fatal("expected checked-out connection to be closed when Put after Close")
	}
	if pool.Len() != 0 {
		t.Fatalf("expected empty pool after Close, got %d", pool.Len())
	}
}

func TestConnectionPool_GetCanceledContext(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.MaxNumConnections = 1

	// Take the only slot.
	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer pool.Put(t.Context(), conn, nil)

	// A second Get must respect context cancellation instead of blocking
	// forever.
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := pool.Get(ctx)
		done <- err
	}()

	// Give the goroutine a moment to block on the condition.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Get did not return after context cancel")
	}
}

func TestConnectionPool_CloseUnblocksWaiters(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.MaxNumConnections = 1

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer pool.Put(t.Context(), conn, nil)

	done := make(chan error, 1)
	go func() {
		_, err := pool.Get(t.Context())
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := pool.Close(); err != nil {
		t.Fatalf("unexpected error closing pool: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, dnsResolverErrors.ErrClosedPool) {
			t.Fatalf("expected ErrClosedPool, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Get was not unblocked by Close")
	}
}

// A connection idle past IdleTimeout must not be handed back out by Get; it
// should be closed and a fresh one dialed instead.
func TestConnectionPool_IdleEvictionOnGet(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var created []*mockConnection
	pool := connection_pool.New(func() (*mockConnection, error) {
		mu.Lock()
		defer mu.Unlock()
		conn := &mockConnection{}
		created = append(created, conn)
		return conn, nil
	})
	pool.IdleTimeout = 30 * time.Millisecond

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pool.Put(t.Context(), conn, nil)

	time.Sleep(60 * time.Millisecond)

	conn2, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn2 == conn {
		t.Fatal("expected a fresh connection after idle timeout, got the stale one")
	}

	conn.mu.Lock()
	closed := conn.isClosed
	conn.mu.Unlock()
	if !closed {
		t.Fatal("expected the idle-expired connection to be closed")
	}

	pool.Put(t.Context(), conn2, nil)
}

// Maintain must evict surplus connections (outside the warm set) that have been
// idle past IdleTimeout.
func TestConnectionPool_MaintainEvictsIdle(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.IdleTimeout = 20 * time.Millisecond // MinIdleConnections stays 0 → all surplus.

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pool.Put(t.Context(), conn, nil)
	if pool.Len() != 1 {
		t.Fatalf("expected pool length 1, got %d", pool.Len())
	}

	time.Sleep(40 * time.Millisecond)
	pool.Maintain(t.Context())

	if pool.Len() != 0 {
		t.Fatalf("expected idle connection to be evicted, got %d", pool.Len())
	}
	conn.mu.Lock()
	closed := conn.isClosed
	conn.mu.Unlock()
	if !closed {
		t.Fatal("expected the evicted connection to be closed")
	}
}

// Maintain must dial connections up to MinIdleConnections.
func TestConnectionPool_MaintainReplenishesWarm(t *testing.T) {
	t.Parallel()

	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.MinIdleConnections = 3

	pool.Maintain(t.Context())

	if pool.Len() != 3 {
		t.Fatalf("expected 3 warm connections, got %d", pool.Len())
	}
}

// A successful Ping keeps a warm connection alive even past IdleTimeout, and the
// same connection is reused (not replaced).
func TestConnectionPool_MaintainPingKeepsWarm(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var pings int
	pool := connection_pool.New(func() (*mockConnection, error) {
		return newMockConnection()
	})
	pool.MinIdleConnections = 1
	pool.IdleTimeout = 20 * time.Millisecond
	pool.Ping = func(*mockConnection) error {
		mu.Lock()
		pings++
		mu.Unlock()
		return nil
	}

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pool.Put(t.Context(), conn, nil)

	time.Sleep(40 * time.Millisecond) // exceeds IdleTimeout
	pool.Maintain(t.Context())

	if pool.Len() != 1 {
		t.Fatalf("expected warm connection retained, got %d", pool.Len())
	}
	mu.Lock()
	got := pings
	mu.Unlock()
	if got != 1 {
		t.Fatalf("expected exactly 1 ping, got %d", got)
	}

	reused, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reused != conn {
		t.Fatal("expected the same warm connection to be kept alive")
	}
	pool.Put(t.Context(), reused, nil)
}

// A failed Ping discards the warm connection (closing it) and replenishment
// dials a replacement.
func TestConnectionPool_MaintainPingFailureReplaces(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var created []*mockConnection
	pool := connection_pool.New(func() (*mockConnection, error) {
		mu.Lock()
		defer mu.Unlock()
		conn := &mockConnection{}
		created = append(created, conn)
		return conn, nil
	})
	pool.MinIdleConnections = 1
	pool.Ping = func(*mockConnection) error {
		return errDeadConnection
	}

	conn, err := pool.Get(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pool.Put(t.Context(), conn, nil)

	pool.Maintain(t.Context())

	if pool.Len() != 1 {
		t.Fatalf("expected 1 warm connection after replacement, got %d", pool.Len())
	}
	conn.mu.Lock()
	closed := conn.isClosed
	conn.mu.Unlock()
	if !closed {
		t.Fatal("expected the ping-failed connection to be closed")
	}
	mu.Lock()
	n := len(created)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("expected a replacement to be dialed (2 created), got %d", n)
	}
}
