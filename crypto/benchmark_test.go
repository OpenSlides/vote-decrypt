package crypto_test

import (
	"crypto/ecdh"
	"testing"

	"github.com/OpenSlides/vote-decrypt/crypto"
)

func benchmarkDecrypt(b *testing.B, voteCount int, voteByteSize int) {
	curve := ecdh.X25519()
	cr := crypto.New(mockMainKey(), randomMock{}, curve)

	plaintext := make([]byte, voteByteSize)

	privKey, err := curve.GenerateKey(randomMock{})
	if err != nil {
		b.Fatalf("creating private key: %v", err)
	}

	pubKey := privKey.PublicKey().Bytes()

	votes := make([][]byte, voteCount)
	for i := 0; i < voteCount; i++ {
		encrypted, err := crypto.Encrypt(randomMock{}, curve, pubKey, plaintext)
		if err != nil {
			b.Fatalf("encrypting vote: %v", err)
		}
		votes[i] = encrypted
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for i := 0; i < voteCount; i++ {
			if _, err := cr.Decrypt(privKey.Bytes(), votes[i]); err != nil {
				b.Errorf("decrypting: %v", err)
			}
		}
	}
}

func BenchmarkDecrypt_1Votes_Byte100(b *testing.B)    { benchmarkDecrypt(b, 1, 100) }
func BenchmarkDecrypt_10Votes_Byte100(b *testing.B)   { benchmarkDecrypt(b, 10, 100) }
func BenchmarkDecrypt_100Votes_Byte100(b *testing.B)  { benchmarkDecrypt(b, 100, 100) }
func BenchmarkDecrypt_1000Votes_Byte100(b *testing.B) { benchmarkDecrypt(b, 1_000, 100) }

// func BenchmarkDecrypt_10000Votes_Byte100(b *testing.B)  { benchmarkDecrypt(b, 10_000, 100) }
// func BenchmarkDecrypt_100000Votes_Byte100(b *testing.B) { benchmarkDecrypt(b, 100_000, 100) }

func BenchmarkDecrypt_1Votes_Byte1000(b *testing.B)    { benchmarkDecrypt(b, 1, 1_000) }
func BenchmarkDecrypt_10Votes_Byte1000(b *testing.B)   { benchmarkDecrypt(b, 10, 1_000) }
func BenchmarkDecrypt_100Votes_Byte1000(b *testing.B)  { benchmarkDecrypt(b, 100, 1_000) }
func BenchmarkDecrypt_1000Votes_Byte1000(b *testing.B) { benchmarkDecrypt(b, 1_000, 1_000) }
