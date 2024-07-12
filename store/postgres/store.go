// Package postgres is a storrage backend for vote-decrypt that uses postgres.
package postgres

import (
	"context"
	"crypto/subtle"
	_ "embed" // Needed for file embedding
	"fmt"
	"time"

	"github.com/OpenSlides/vote-decrypt/errorcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Store implements the decrypt.Store interface by writing the data to postgres.
type Store struct {
	pool *pgxpool.Pool
}

// New initializes a new Store.
func New(ctx context.Context, connString string) (*Store, error) {
	conf, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("invalid connection url: %w", err)
	}

	// Fix issue with gbBouncer. The documentation says, that this make the
	// connection slower. We have to test the performance. Maybe it is better to
	// remove the connection pool here or not use bgBouncer at all.
	//
	// See https://github.com/OpenSlides/openslides-vote-service/pull/66
	conf.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	s := Store{
		pool: pool,
	}

	s.Wait(ctx)

	if err := s.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return &s, nil
}

// Wait blocks until a connection to postgres can be established.
func (s *Store) Wait(ctx context.Context) {
	for ctx.Err() == nil {
		err := s.pool.Ping(ctx)
		if err == nil {
			return
		}
		fmt.Printf("Waiting for postgres: %v", err)
		time.Sleep(500 * time.Millisecond)
	}
}

// Migrate creates the database schema.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("creating schema: %w", err)
	}
	return nil
}

// Close closes all connections. It blocks, until all connection are closed.
func (s *Store) Close() {
	s.pool.Close()
}

// SaveKey stores the private key.
//
// Has to return an error, if a key already exists.
func (s *Store) SaveKey(ctx context.Context, id string, key []byte) error {
	sql := `INSERT INTO vote_decrypt.poll (id, key) VALUES ($1, $2);`
	if _, err := s.pool.Exec(ctx, sql, id, key); err != nil {
		return fmt.Errorf("insert key: %w", err)
	}

	return nil
}

// LoadKey returns the private key from the store.
//
// If the poll is unknown return (nil, nil)
func (s *Store) LoadKey(ctx context.Context, id string) ([]byte, error) {
	sql := `SELECT key FROM vote_decrypt.poll where id = $1`

	var key []byte
	if err := s.pool.QueryRow(ctx, sql, id).Scan(&key); err != nil {
		return nil, fmt.Errorf("fetching key: %w", err)
	}

	return key, nil
}

// ValidateSignature makes sure, that no other signature is saved for a
// poll. Saves the signature for future calls.
//
// Has to return an error if the id is unknown in the store.
func (s *Store) ValidateSignature(ctx context.Context, id string, hash []byte) error {
	err := pgx.BeginTxFunc(
		ctx,
		s.pool,
		pgx.TxOptions{
			IsoLevel: "REPEATABLE READ",
		},
		func(tx pgx.Tx) error {
			sql := `SELECT hash FROM vote_decrypt.poll where id = $1`
			var currentHash []byte
			if err := s.pool.QueryRow(ctx, sql, id).Scan(&currentHash); err != nil {
				return fmt.Errorf("fetching key: %w", err)
			}

			if currentHash != nil {
				if subtle.ConstantTimeCompare(hash, currentHash) != 1 {
					return errorcode.Invalid
				}
				return nil
			}

			sql = "UPDATE vote_decrypt.poll SET hash = $2 WHERE id = $1 AND hash IS NULL;"
			if _, err := s.pool.Exec(ctx, sql, id, hash); err != nil {
				return fmt.Errorf("write hash: %w", err)
			}

			return nil

		},
	)

	return err
}

// ClearPoll removes all data for the poll.
func (s *Store) ClearPoll(ctx context.Context, id string) error {
	sql := "DELETE FROM vote_decrypt.poll WHERE id = $1"
	if _, err := s.pool.Exec(ctx, sql, id); err != nil {
		return fmt.Errorf("deleting data of poll %s: %w", id, err)
	}
	return nil
}
