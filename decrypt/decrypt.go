// Package decrypt implements the protocoll of the service to start a poll and
// decrypt a list of votes.
//
// The service as to be initialized with decrypt.New(crypto_backend, storage_backend, [options...]).
package decrypt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"runtime"
	"sync"

	"github.com/OpenSlides/vote-decrypt/errorcode"
)

// Decrypt holds the internal state of the decrypt component.
type Decrypt struct {
	crypto Crypto
	store  Store

	maxVotes          int // maximum votes per poll.
	decryptWorkers    int
	random            io.Reader
	listToContent     func(pollID string, decrypted [][]byte) ([]byte, error) // See WithListToContent()
	decryptErrorValue []byte                                                  // Value to use if a vote can not be decrypted.
}

// New returns the initialized decrypt component.
func New(crypto Crypto, store Store, options ...Option) *Decrypt {
	d := Decrypt{
		crypto:            crypto,
		store:             store,
		decryptWorkers:    runtime.GOMAXPROCS(-1),
		random:            rand.Reader,
		maxVotes:          math.MaxInt,
		listToContent:     jsonListToContent,
		decryptErrorValue: []byte(`{"error":"encryption not valid"}`),
	}

	for _, o := range options {
		o(&d)
	}

	return &d
}

// PublicMainKey returns the public main key.
func (d *Decrypt) PublicMainKey(ctx context.Context) []byte {
	return d.crypto.PublicMainKey()
}

// Start starts the poll. Returns a public poll key.
//
// It generates a cryptographic key, saves the poll meta data and returns the
// public key. It also returns a signature of the public key created with the
// main key.
//
// If the method is called multiple times with the same pollID, it returns the
// same public key. This is at least true until Clear() is called.
func (d *Decrypt) Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error) {
	if err := d.validateID(pollID); err != nil {
		return nil, nil, fmt.Errorf("invalid poll id: %w", err)
	}

	// TODO: Load Key and CreatePoll Key have probably be atomic.
	pollKey, err := d.store.LoadKey(pollID)
	if err != nil {
		if !errors.Is(err, errorcode.NotExist) {
			return nil, nil, fmt.Errorf("loading poll key: %w", err)
		}

		key, err := d.crypto.CreatePollKey()
		if err != nil {
			return nil, nil, fmt.Errorf("creating poll key: %w", err)
		}

		pollKey = key
		if err := d.store.SaveKey(pollID, key); err != nil {
			return nil, nil, fmt.Errorf("saving poll key: %w", err)
		}
	}

	pubKey, pubKeySig, err = d.crypto.PublicPollKey(pollKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing pub key: %w", err)
	}

	// Log the pubKey as base64 as long as the backend does not support his
	log.Printf("public poll key for poll %s is %s", pollID, base64.StdEncoding.EncodeToString(pubKey))
	return pubKey, pubKeySig, nil
}

// Stop takes a list of ecrypted votes, decryptes them and returns them in a
// random order together with a signature.
//
// If the function is called multiple times with the same pollID and voteList,
// it returns the same output. But if fails if it is called with different
// votes.
//
// TODO: This implementation is wrong. Not the output has to be hashed and saved, but the input.
func (d *Decrypt) Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error) {
	pollKey, err := d.store.LoadKey(pollID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading poll key: %w", err)
	}

	if len(voteList) > d.maxVotes {
		return nil, nil, fmt.Errorf("received %d votes, only %d votes supported: %w", len(voteList), d.maxVotes, errorcode.Invalid)
	}

	decrypted, err := d.decryptVotes(pollKey, voteList)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting votes: %w", err)
	}

	decryptedContent, err = d.listToContent(pollID, decrypted)
	if err != nil {
		return nil, nil, fmt.Errorf("creating content: %w", err)
	}

	signature = d.crypto.Sign(decryptedContent)

	// This has to be the last step of this function to protect agains timing
	// attacks. All other steps have to be run, even when the calll is doomed to
	// fail in this step
	if err := d.store.ValidateSignature(pollID, signature); err != nil {
		if errors.Is(err, errorcode.Invalid) {
			return nil, nil, fmt.Errorf("stop was called with different parameters before")
		}
		return nil, nil, fmt.Errorf("validate signature: %w", err)
	}

	return decryptedContent, signature, nil
}

// Clear stops a poll by removing the generated cryptographic key.
func (d *Decrypt) Clear(ctx context.Context, pollID string) error {
	if err := d.store.ClearPoll(pollID); err != nil {
		return fmt.Errorf("clearing poll from store: %w", err)
	}
	return nil
}

// randInt returns a random int between 0 and n from a random source like crypt.Reader
func randInt(source io.Reader, n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}

	r, err := rand.Int(source, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("getting random number from rand.Int: %w", err)
	}

	return int(r.Int64()), nil
}

// decryptVotes decrypts a list of votes and returns them decrypted in random
// order.
//
// Uses `d.decrptWorkers` parallel goroutines.
func (d *Decrypt) decryptVotes(key []byte, voteList [][]byte) ([][]byte, error) {
	voteChan := make(chan []byte, 1)

	// Choose a random vote from the voteList and sends them to voteChan.
	go func() {
		defer close(voteChan)

		n := len(voteList)
		for n > 0 {
			i, err := randInt(d.random, n-1)
			if err != nil {
				// TODO: handle error
				panic(err)
			}

			voteChan <- voteList[i]
			voteList[i] = voteList[n-1]
			n--
		}
	}()

	// Decrypt votes in parallel using multiple "decrypt workers". Receiving the
	// votes from voteChan and sending them to decryptedChan.
	var wg sync.WaitGroup
	wg.Add(d.decryptWorkers)
	decryptedChan := make(chan []byte, 1)
	for i := 0; i < d.decryptWorkers; i++ {
		go func() {
			defer wg.Done()
			for vote := range voteChan {
				decrypted, err := d.crypto.Decrypt(key, vote)
				if err != nil {
					// TODO: Is is allowed to log the error?
					log.Printf("TODO: vote: %v", err)
					decrypted = d.decryptErrorValue
				}

				decryptedChan <- decrypted
			}
		}()
	}

	// Close the decryptedChan when all the decryption is done.
	go func() {
		wg.Wait()
		close(decryptedChan)
	}()

	// Bundle decrypted votes.
	decryptedList := make([][]byte, len(voteList))
	var i int
	for decrypted := range decryptedChan {
		decryptedList[i] = decrypted
		i++
	}
	return decryptedList, nil
}

// validateID makes sure, the id can be used for the filesystem store.
func (d *Decrypt) validateID(id string) error {
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '/' || c == '.') {
			return fmt.Errorf("id contains invalid character %c: %w", c, errorcode.Invalid)
		}
	}
	return nil
}

// Crypto implements all required cryptographic functions.
type Crypto interface {
	// CreatePollKey creates a new keypair for a poll.
	CreatePollKey() ([]byte, error)

	// PublicPollKey returns the public poll key and the signature for a given key.
	PublicPollKey(key []byte) (pubKey []byte, pubKeySig []byte, err error)

	// Decrypt returned the plaintext from value using the key.
	Decrypt(key []byte, value []byte) ([]byte, error)

	// Sign returns the signature for the given data.
	Sign(value []byte) []byte

	// PublicMainKey returns the public main key.
	PublicMainKey() []byte
}

// Store saves the data, that have to be persistent.
type Store interface {
	// SaveKey stores the private key.
	//
	// Has to return an error `errorcode.Exist` if the key is already known.
	SaveKey(id string, key []byte) error

	// LoadKey returns the private key from the store.
	//
	// If the poll is unknown return `errorcode.NotExist`
	LoadKey(id string) (key []byte, err error)

	// ValidateSignature makes sure, that no other signature is saved for a
	// poll. Saves the signature for future calls.
	//
	// Has to return `errorcode.Invalid` if the hash differs from a privious
	// call.
	//
	// Has to return `errorcode.NotExist` when the id does not exist.
	ValidateSignature(id string, hash []byte) error

	// ClearPoll removes all data for the poll.
	//
	// Does not return an error if poll does not exist.
	ClearPoll(id string) error
}

// jsonListToContent creates one byte slice from a list of votes in json format.
func jsonListToContent(pollID string, decrypted [][]byte) ([]byte, error) {
	votes := make([]json.RawMessage, len(decrypted))
	for i, vote := range decrypted {
		votes[i] = vote
	}

	content := struct {
		ID    string            `json:"id"`
		Votes []json.RawMessage `json:"votes"`
	}{
		pollID,
		votes,
	}

	decryptedContent, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal decrypted content: %w", err)
	}

	return decryptedContent, nil
}
