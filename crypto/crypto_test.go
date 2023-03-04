package crypto_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"testing"

	"github.com/OpenSlides/vote-decrypt/crypto"
)

func TestCreatePollKey(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{}, nil)

	key, err := c.CreatePollKey()
	if err != nil {
		t.Fatalf("CreatePollKey: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("created key is not valid")
	}
}

func TestPublicPollKey(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{}, nil)

	pub, sig, err := c.PublicPollKey(mockPollKey())
	if err != nil {
		t.Fatalf("PublicPollKey: %v", err)
	}

	if !ed25519.Verify(ed25519.NewKeyFromSeed(mockMainKey()).Public().(ed25519.PublicKey), pub, sig) {
		t.Errorf("signature does not match public key")
	}
}

func TestDecrypt(t *testing.T) {
	curve := ecdh.X25519()

	c := crypto.New(mockMainKey(), randomMock{}, curve)

	plaintext := "this is my vote"

	privKey, err := curve.GenerateKey(randomMock{})
	if err != nil {
		t.Fatalf("creating private key: %v", err)
	}
	pubKey := privKey.PublicKey().Bytes()

	encrypted, err := crypto.Encrypt(randomMock{}, curve, pubKey, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypting plaintext: %v", err)
	}

	decrypted, err := c.Decrypt(privKey.Bytes(), encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("decrypt got `%s`, expected `%s`", decrypted, plaintext)
	}
}

func TestSign(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{}, nil)

	data := []byte("this is my value")

	sig := c.Sign(data)

	if !ed25519.Verify(ed25519.NewKeyFromSeed(mockMainKey()).Public().(ed25519.PublicKey), data, sig) {
		t.Errorf("signature does not match public key")
	}
}

func mockPollKey() []byte {
	return make([]byte, 32)
}

func mockMainKey() []byte {
	return make([]byte, 32)
}

type randomMock struct{}

func (r randomMock) Read(data []byte) (n int, err error) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
	return len(data), nil
}
