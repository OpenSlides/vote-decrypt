// Package crypto implements the cryptographic methods needed by the service.
//
// The crypto object has to be initialized with crypto.New(MAIN_KEY,
// RANDOM_SOURCE).
//
// The main porpuse of this package is to handle the main key, create short
// living poll keys and decrypt single votes that where encrypted with this poll
// key.
//
// This package uses x25519 for decryption and ed25519 for signing.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	pubKeySize = 32
	nonceSize  = 12
)

// curve sets the ecdh curve to use in this packages.
//
// In theory all curves supported from the go ecdh package could be used. But in
// practice, only x25519 works. The reason is, that only x25519 has a fix key
// size (the the constant pubKeySize). The ciphertext this service uses contains
// the public key at the first `pubKeySize` bytes. With a variable size key, it
// is not possible to know, where the key ends end the decoded bytes begin. To
// support other curves, we have the encode the ciphertext in another way.
var curve = ecdh.X25519()

// Crypto implements all cryptographic functions needed for the decrypt service.
type Crypto struct {
	mainKey ed25519.PrivateKey
	random  io.Reader
}

// New initializes a Crypto object with a main key and a random source.
//
// mainKey has to be a 32 byte slice that represents a ed25519 key.
func New(mainKey []byte, random io.Reader) Crypto {
	return Crypto{
		mainKey: ed25519.NewKeyFromSeed(mainKey),
		random:  random,
	}
}

// PublicMainKey returns the public key for the private main key.
func (c Crypto) PublicMainKey() []byte {
	return c.mainKey.Public().(ed25519.PublicKey)
}

// CreatePollKey creates a new keypair for a poll.
//
// This implementation returns the first 32 bytes from the random source.
func (c Crypto) CreatePollKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(c.random, key); err != nil {
		return nil, fmt.Errorf("read from random source: %w", err)
	}

	return key, nil
}

// PublicPollKey returns the public poll key and the signature for the given
// key.
func (c Crypto) PublicPollKey(privateKey []byte) (pubKey []byte, pubKeySig []byte, err error) {
	privKey, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private poll key: %w", err)
	}

	pubKey = privKey.PublicKey().Bytes()

	pubKeySig = ed25519.Sign(c.mainKey, pubKey)

	return pubKey, pubKeySig, nil
}

// Decrypt returned the plaintext from value using the key.
//
// ciphertext contains three values. The first 32 bytes is the public empheral
// key from the client. The next 12 byte is the used nonce for aes-gcm. All
// later bytes are the encrypted vote.
//
// This function uses x25519 as described in rfc 7748. It uses hkdf with sha256
// for the key derivation.
func (c Crypto) Decrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < pubKeySize+nonceSize+aes.BlockSize {
		return nil, fmt.Errorf("invalid cipher")
	}

	ephemeralPublicKey, err := curve.NewPublicKey(ciphertext[:pubKeySize])
	if err != nil {
		return nil, fmt.Errorf("invalid publick key in ciphertext: %w", err)
	}

	nonce := ciphertext[pubKeySize : pubKeySize+nonceSize]

	privKey, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("initializing private key: %w", err)
	}

	sharedSecred, err := privKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating shared secred: %w", err)
	}

	hkdf := hkdf.New(sha256.New, sharedSecred, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("generate key with hkdf: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating aes chipher: %w", err)
	}

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm mode: %w", err)
	}

	plaintext, err := mode.Open(nil, nonce, ciphertext[pubKeySize+nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting ciphertext: %w", err)
	}

	return plaintext, nil
}

// Sign returns the signature for the given data.
func (c Crypto) Sign(value []byte) []byte {
	return ed25519.Sign(c.mainKey, value)
}

// Encrypt creates a cyphertext from plaintext using the given public key.
//
// This function is not needed or used by the decrypt service. It is only
// implemented in this package for debugging and testing.
//
// It creates a new shared key by creating a new random private key and the
// given public key.
//
// It returns the created public key (32 byte) the noonce (12 byte) and the
// encrypted value of the given plaintext.
func Encrypt(random io.Reader, publicPollKey []byte, plaintext []byte) ([]byte, error) {
	ephemeralPrivateKey, err := curve.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("creating ephemeral private key: %w", err)
	}

	cipherPrefix := ephemeralPrivateKey.PublicKey().Bytes()

	remotePublicKey, err := curve.NewPublicKey(publicPollKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	sharedSecred, err := ephemeralPrivateKey.ECDH(remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating shared secred: %w", err)
	}

	hkdf := hkdf.New(sha256.New, sharedSecred, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("generate key with hkdf: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating aes chipher: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := random.Read(nonce); err != nil {
		return nil, fmt.Errorf("read random for nonce: %w", err)
	}
	cipherPrefix = append(cipherPrefix, nonce...)

	mode, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm mode: %w", err)
	}

	encrypted := mode.Seal(nil, nonce, plaintext, nil)

	return append(cipherPrefix, encrypted...), nil
}

// Verify checks that the the signature was created with pubKey for the message.
//
// This function is not needed or used by the decrypt service. It is only
// implemented in this package for debugging and testing.
func Verify(pubKey, message, signature []byte) bool {
	return ed25519.Verify(pubKey, message, signature)
}
