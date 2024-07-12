// Package filesystem is a storrage backend for vote-decrypt that uses the file
// system.
package filesystem

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/OpenSlides/vote-decrypt/errorcode"
)

// Store implements the decrypt.Store interface by writing the data to files.
//
// If only one instance of the decrypt service is running, this is concurrency
// save. If more then one process is running, it depends on the features of the
// filesystem.
//
// For each poll, two files are created. `POLLID_key` that contains the private
// key for the poll and `POLLID_hash` the contains the hash of the first stop
// request.
//
// TODO: Think about timing attacks when files do not exist or have wrong
// content.
type Store struct {
	mu sync.Mutex

	path string
}

// New initializes a new Store.
func New(path string) *Store {
	return &Store{
		path: path,
	}
}

// SaveKey stores the private key.
//
// Has to return an error, if a key already exists.
func (s *Store) SaveKey(_ context.Context, id string, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.path == "" {
		return fmt.Errorf("no data dir provided. Check the environment variable VOTE_DECRYPT_STORE")
	}

	if err := os.MkdirAll(s.path, os.ModePerm); err != nil {
		return fmt.Errorf("creating data dir `%s`: %w", s.path, err)
	}

	f, err := os.OpenFile(s.keyFile(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errorcode.Exist
		}
		return fmt.Errorf("create file: %w", err)
	}

	defer func() {
		if cErr := f.Close(); err == nil && cErr != nil {
			err = fmt.Errorf("closing file: %w", err)
		}
	}()

	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	return nil
}

// LoadKey returns the private key from the store.
//
// If the poll is unknown return (nil, nil)
func (s *Store) LoadKey(_ context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := os.ReadFile(s.keyFile(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errorcode.NotExist
		}
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	return key, nil
}

// ValidateSignature makes sure, that no other signature is saved for a
// poll. Saves the signature for future calls.
//
// Has to return an error if the id is unknown in the store.
func (s *Store) ValidateSignature(_ context.Context, id string, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.keyFile(id)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errorcode.NotExist
		}

		return fmt.Errorf("checking key file: %w", err)
	}

	f, err := os.OpenFile(s.hashFile(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return s.checkHash(id, hash)
		}

		return fmt.Errorf("create file: %w", err)
	}

	defer func() {
		if cErr := f.Close(); err == nil && cErr != nil {
			err = fmt.Errorf("closing file: %w", err)
		}
	}()

	if _, err := f.Write(hash); err != nil {
		return fmt.Errorf("writing hash: %w", err)
	}

	return nil
}

func (s *Store) checkHash(id string, hash []byte) error {
	content, err := os.ReadFile(s.hashFile(id))
	if err != nil {
		return fmt.Errorf("reading file content: %v", err)
	}

	if subtle.ConstantTimeCompare(hash, content) != 1 {
		return errorcode.Invalid
	}

	return nil
}

// ClearPoll removes all data for the poll.
func (s *Store) ClearPoll(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.keyFile(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting key file: %w", err)
	}

	if err := os.Remove(s.hashFile(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting hash file: %w", err)
	}

	return nil
}

func (s *Store) keyFile(id string) string {
	id = strings.ReplaceAll(id, "/", "_")
	return path.Join(s.path, id+".key")
}

func (s *Store) hashFile(id string) string {
	id = strings.ReplaceAll(id, "/", "_")
	return path.Join(s.path, id+".hash")
}
