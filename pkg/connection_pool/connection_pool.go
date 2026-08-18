package connection_pool

import (
	"container/list"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	dnsResolverErrors "dns_resolver/pkg/errors"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
)

// idleConnection pairs a pooled connection with the time it was last returned
// to the pool, so the pool can reason about how long it has been idle.
type idleConnection[T io.Closer] struct {
	connection T
	idleSince  time.Time
}

type Pool[T io.Closer] struct {
	MaxNumConnections int
	MakeConnection    func() (T, error)

	// IdleTimeout, when > 0, causes a connection that has sat idle in the pool
	// for longer than this to be discarded rather than handed out or retained.
	// It is enforced lazily on Get and proactively by Maintain. The warm set
	// (see MinIdleConnections) is exempt.
	IdleTimeout time.Duration

	// MinIdleConnections, when > 0, is the number of warm connections Maintain
	// tries to keep available, dialing replacements up to this count (bounded
	// by MaxNumConnections).
	MinIdleConnections int

	// Ping, when non-nil, is used by Maintain to health-check / keep alive the
	// warm set. A warm connection whose Ping returns an error is discarded (and
	// replenished); a successful Ping refreshes the connection's idle clock.
	Ping func(T) error

	numActiveConnections int
	condition            *sync.Cond
	connections          *list.List
	mutex                *sync.Mutex
	closed               bool
}

func New[T io.Closer](fn func() (T, error)) *Pool[T] {
	mutex := new(sync.Mutex)
	return &Pool[T]{
		MaxNumConnections: 5,
		MakeConnection:    fn,
		mutex:             mutex,
		connections:       list.New(),
		condition:         sync.NewCond(mutex),
	}
}

// closeConnection closes a connection (expected to be called without holding
// the pool lock), logging anything other than an already-closed error.
func (pool *Pool[T]) closeConnection(ctx context.Context, connection T) {
	if io.Closer(connection) == nil {
		return
	}
	if closeErr := connection.Close(); closeErr != nil && !motmedelErrors.IsClosedError(closeErr) {
		slog.WarnContext(
			motmedelContext.WithError(
				ctx,
				motmedelErrors.NewWithTrace(fmt.Errorf("connection close: %w", closeErr), connection),
			),
			"An error occurred when closing a connection.",
		)
	}
}

func (pool *Pool[T]) Get(ctx context.Context) (T, error) {
	var zero T

	if err := ctx.Err(); err != nil {
		return zero, err
	}

	// Connections found to be idle-expired while searching for a usable one are
	// closed after the lock is released.
	var staleConnections []T
	defer func() {
		for _, connection := range staleConnections {
			pool.closeConnection(ctx, connection)
		}
	}()

	pool.mutex.Lock()

	// Watchdog: if ctx is cancelled while we're waiting on the condition
	// variable, broadcast so the Wait() unblocks and we can return ctx.Err().
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			pool.mutex.Lock()
			pool.condition.Broadcast()
			pool.mutex.Unlock()
		case <-stop:
		}
	}()

	for {
		if pool.closed {
			pool.mutex.Unlock()
			return zero, motmedelErrors.NewWithTrace(dnsResolverErrors.ErrClosedPool)
		}
		if err := ctx.Err(); err != nil {
			pool.mutex.Unlock()
			return zero, err
		}

		// Hand out the most-recently-used idle connection, skipping (and
		// scheduling for close) any that have exceeded IdleTimeout.
		for pool.connections.Len() > 0 {
			element := pool.connections.Remove(pool.connections.Front())

			idle, ok := element.(idleConnection[T])
			if !ok {
				pool.mutex.Unlock()
				return zero, motmedelErrors.NewWithTrace(
					fmt.Errorf("%w (generic io.Closer)", motmedelErrors.ErrConversionNotOk),
					element,
				)
			}

			connection := idle.connection
			if io.Closer(connection) == nil {
				pool.numActiveConnections--
				pool.condition.Signal()
				continue
			}

			if pool.IdleTimeout > 0 && time.Since(idle.idleSince) > pool.IdleTimeout {
				pool.numActiveConnections--
				pool.condition.Signal()
				staleConnections = append(staleConnections, connection)
				continue
			}

			pool.mutex.Unlock()
			return connection, nil
		}

		if pool.numActiveConnections < pool.MaxNumConnections {
			break
		}
		pool.condition.Wait()
	}

	// Reserve a slot and dial without holding the lock so other callers
	// aren't blocked while a potentially-slow dial is in progress.
	pool.numActiveConnections++
	pool.mutex.Unlock()

	connection, err := pool.MakeConnection()
	if err != nil {
		pool.mutex.Lock()
		pool.numActiveConnections--
		pool.condition.Signal()
		pool.mutex.Unlock()
		return zero, fmt.Errorf("make connection: %w", err)
	}
	if io.Closer(connection) == nil {
		pool.mutex.Lock()
		pool.numActiveConnections--
		pool.condition.Signal()
		pool.mutex.Unlock()
		return zero, motmedelErrors.NewWithTrace(nil_error.New("connection"))
	}

	pool.mutex.Lock()
	if pool.closed {
		pool.numActiveConnections--
		pool.condition.Broadcast()
		pool.mutex.Unlock()
		_ = connection.Close()
		return zero, motmedelErrors.NewWithTrace(dnsResolverErrors.ErrClosedPool)
	}
	pool.mutex.Unlock()

	return connection, nil
}

func (pool *Pool[T]) Put(ctx context.Context, connection T, err error) {
	if io.Closer(connection) == nil {
		return
	}

	pool.mutex.Lock()

	if err != nil || pool.closed {
		pool.numActiveConnections--
		pool.condition.Signal()
		pool.mutex.Unlock()

		pool.closeConnection(ctx, connection)
		return
	}

	pool.connections.PushFront(idleConnection[T]{connection: connection, idleSince: time.Now()})
	pool.condition.Signal()
	pool.mutex.Unlock()
}

// Maintain runs a single maintenance pass: it health-checks/keep-alives the
// warm set via Ping, evicts surplus connections idle past IdleTimeout, and
// dials replacements up to MinIdleConnections. It is safe to call concurrently
// with Get/Put and is a no-op unless at least one of IdleTimeout,
// MinIdleConnections or Ping is configured.
func (pool *Pool[T]) Maintain(ctx context.Context) {
	if pool.IdleTimeout <= 0 && pool.MinIdleConnections <= 0 && pool.Ping == nil {
		return
	}

	// Take ownership of the currently-idle connections. numActiveConnections
	// still counts them, so a concurrent Get below the cap can dial its own
	// connection rather than block on us.
	pool.mutex.Lock()
	if pool.closed {
		pool.mutex.Unlock()
		return
	}
	idleConnections := make([]idleConnection[T], 0, pool.connections.Len())
	for element := pool.connections.Front(); element != nil; element = element.Next() {
		if idle, ok := element.Value.(idleConnection[T]); ok {
			idleConnections = append(idleConnections, idle)
		}
	}
	pool.connections.Init()
	pool.mutex.Unlock()

	now := time.Now()
	survivors := make([]idleConnection[T], 0, len(idleConnections))
	var toClose []T

	for index, idle := range idleConnections {
		connection := idle.connection

		// Keep the most-recently-used MinIdleConnections warm: Ping them (if
		// configured) to validate and reset the upstream's idle timer, dropping
		// any that fail so replenishment dials a healthy replacement. Their
		// idle clock is refreshed so they are exempt from idle eviction.
		if index < pool.MinIdleConnections {
			if pool.Ping != nil {
				if err := pool.Ping(connection); err != nil {
					toClose = append(toClose, connection)
					continue
				}
				idle.idleSince = now
			}
			survivors = append(survivors, idle)
			continue
		}

		// Surplus beyond the warm set: evict if it has been idle too long.
		if pool.IdleTimeout > 0 && now.Sub(idle.idleSince) > pool.IdleTimeout {
			toClose = append(toClose, connection)
			continue
		}
		survivors = append(survivors, idle)
	}

	pool.mutex.Lock()
	if pool.closed {
		pool.numActiveConnections -= len(survivors) + len(toClose)
		pool.mutex.Unlock()
		for _, idle := range survivors {
			pool.closeConnection(ctx, idle.connection)
		}
		for _, connection := range toClose {
			pool.closeConnection(ctx, connection)
		}
		return
	}
	// Return survivors to the back, behind any connections returned via Put
	// while we worked (which are fresher).
	for _, idle := range survivors {
		pool.connections.PushBack(idle)
	}
	if len(toClose) > 0 {
		pool.numActiveConnections -= len(toClose)
	}
	if len(survivors) > 0 || len(toClose) > 0 {
		// Wake any waiter so it can pick up a returned connection or notice the
		// freed slots.
		pool.condition.Broadcast()
	}
	pool.mutex.Unlock()

	for _, connection := range toClose {
		pool.closeConnection(ctx, connection)
	}

	pool.replenish(ctx)
}

// StartMaintenance runs Maintain on an interval until ctx is cancelled.
// Intended to be run in its own goroutine.
func (pool *Pool[T]) StartMaintenance(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case <-ctx.Done():
				return
			default:
				pool.Maintain(ctx)
			}
		}
	}
}

// replenish dials new connections until at least MinIdleConnections are
// available (bounded by MaxNumConnections). It returns on the first dial
// failure rather than spinning; the next Maintain pass retries.
func (pool *Pool[T]) replenish(ctx context.Context) {
	if pool.MinIdleConnections <= 0 || pool.MakeConnection == nil {
		return
	}

	for {
		pool.mutex.Lock()
		if pool.closed ||
			pool.connections.Len() >= pool.MinIdleConnections ||
			pool.numActiveConnections >= pool.MaxNumConnections {
			pool.mutex.Unlock()
			return
		}
		pool.numActiveConnections++
		pool.mutex.Unlock()

		connection, err := pool.MakeConnection()
		if err != nil {
			pool.mutex.Lock()
			pool.numActiveConnections--
			pool.condition.Signal()
			pool.mutex.Unlock()

			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("make connection: %w", err)),
				),
				"An error occurred when replenishing a connection.",
			)
			return
		}
		if io.Closer(connection) == nil {
			pool.mutex.Lock()
			pool.numActiveConnections--
			pool.condition.Signal()
			pool.mutex.Unlock()
			return
		}

		pool.mutex.Lock()
		if pool.closed {
			pool.numActiveConnections--
			pool.condition.Broadcast()
			pool.mutex.Unlock()
			_ = connection.Close()
			return
		}
		pool.connections.PushBack(idleConnection[T]{connection: connection, idleSince: time.Now()})
		pool.condition.Signal()
		pool.mutex.Unlock()
	}
}

func (pool *Pool[T]) Close() error {
	pool.mutex.Lock()

	if pool.closed {
		pool.mutex.Unlock()
		return nil
	}
	pool.closed = true

	// Collect idle connections so we can close them outside the lock.
	var toClose []T
	for element := pool.connections.Front(); element != nil; element = element.Next() {
		idle, ok := element.Value.(idleConnection[T])
		if !ok {
			continue
		}
		if io.Closer(idle.connection) != nil {
			toClose = append(toClose, idle.connection)
		}
	}
	pool.connections.Init()
	pool.numActiveConnections -= len(toClose)
	pool.condition.Broadcast()
	pool.mutex.Unlock()

	var firstErr error
	for _, connection := range toClose {
		if err := connection.Close(); err != nil && firstErr == nil {
			firstErr = motmedelErrors.NewWithTrace(fmt.Errorf("connection close: %w", err), connection)
		}
	}
	return firstErr
}

func (pool *Pool[T]) Len() int {
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	return pool.connections.Len()
}
