package ecdh

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

func RandomScalar(random io.Reader, N *big.Int) (*big.Int, error) {
	randLen := new(big.Int).Sub(N, big.NewInt(2)).BitLen()
	randBuf := make([]byte, randLen/8)
	err := nonZeroRandomBytes(randBuf, random)
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(randBuf)
	m = new(big.Int).Add(m, big.NewInt(1))

	return m, nil
}

func (e *PublicKey) KDF(S []byte, kdf_params []byte, hash crypto.Hash) []byte {
	S_len := (e.Curve.Params().P.BitLen() + 7) / 8
	buf := new(bytes.Buffer)
	buf.Write([]byte{0, 0, 0, 1})
	if S_len > len(S) {
		// If we got invalid S (bigger than curve's P), we are going
		// to produce invalid key. Garbage in, garbage out.
		buf.Write(make([]byte, S_len-len(S)))
	}
	buf.Write(S)
	buf.Write(kdf_params)

	hashw := hash.New()

	hashw.Write(buf.Bytes())
	key := hashw.Sum(nil)

	return key
}

// Implements RFC 3394 Key Unwrapping.
func AESKeyUnwrap(key, cipherText []byte) ([]byte, error) {
	if len(cipherText)%8 != 0 {
		return nil, errors.New("cipherText must by a multiple of 64 bits")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nblocks := len(cipherText)/8 - 1

	// 1) Initialize variables.
	// - Set A = C[0]
	var A [aes.BlockSize]byte
	copy(A[:8], cipherText[:8])

	// For i = 1 to n
	//   Set R[i] = C[i]
	R := make([]byte, len(cipherText)-8)
	copy(R, cipherText[8:])

	// 2) Compute intermediate values.
	for j := 5; j >= 0; j-- {
		for i := nblocks - 1; i >= 0; i-- {
			// B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
			// A = MSB(64, B)
			t := uint64(nblocks*j + i + 1)
			At := binary.BigEndian.Uint64(A[:8]) ^ t
			binary.BigEndian.PutUint64(A[:8], At)

			copy(A[8:], R[i*8:i*8+8])
			cipher.Decrypt(A[:], A[:])

			// R[i] = LSB(B, 64)
			copy(R[i*8:i*8+8], A[8:])
		}
	}

	// 3) Output results.
	// If A is an appropriate initial value (see 2.2.3),
	for i := 0; i < 8; i++ {
		if A[i] != 0xA6 {
			return nil, errors.New("Failed to unwrap key (A is not IV).")
		}
	}

	return R, nil
}

// Implements RFC 3394 Key Wrapping.
func AESKeyWrap(key, plainText []byte) ([]byte, error) {
	if len(plainText)%8 != 0 {
		return nil, errors.New("plainText must be a multiple of 64 bits")
	}

	cipher, err := aes.NewCipher(key) // NewCipher checks key size
	if err != nil {
		return nil, err
	}

	nblocks := len(plainText) / 8

	// 1) Initialize variables.
	var A [aes.BlockSize]byte
	// Section 2.2.3.1 -- Initial Value
	// http://tools.ietf.org/html/rfc3394#section-2.2.3.1
	for i := 0; i < 8; i++ {
		A[i] = 0xA6
	}

	// For i = 1 to n
	//   Set R[i] = P[i]
	R := make([]byte, len(plainText))
	copy(R, plainText)

	// 2) Calculate intermediate values.
	for j := 0; j <= 5; j++ {
		for i := 0; i < nblocks; i++ {
			// B = AES(K, A | R[i])
			copy(A[8:], R[i*8:i*8+8])
			cipher.Encrypt(A[:], A[:])

			// (Assume B = A)
			// A = MSB(64, B) ^ t where t = (n*j)+1
			t := uint64(j*nblocks + i + 1)
			At := binary.BigEndian.Uint64(A[:8]) ^ t
			binary.BigEndian.PutUint64(A[:8], At)

			// R[i] = LSB(64, B)
			copy(R[i*8:i*8+8], A[8:])
		}
	}

	// 3) Output results.
	// Set C[0] = A
	// For i = 1 to n
	//   C[i] = R[i]
	return append(A[:8], R...), nil
}

func PadBuffer(buf []byte, block_len int) []byte {
	padding := block_len - (len(buf) % block_len)
	if padding == 0 {
		return buf
	}

	pad_buf := make([]byte, padding)
	for i := 0; i < padding; i += 1 {
		pad_buf[i] = byte(padding)
	}

	return append(buf, pad_buf...)
}

func UnpadBuffer(buf []byte, data_len int) []byte {
	padding := len(buf) - data_len
	out_buf := buf[:data_len]

	for i := data_len; i < len(buf); i += 1 {
		if buf[i] != byte(padding) {
			// Invalid padding - bail out
			return nil
		}
	}

	return out_buf
}

func (e *PublicKey) Encrypt(random io.Reader, kdf_params []byte, plain []byte, hash crypto.Hash) (Vx *big.Int, Vy *big.Int, C []byte, err error) {
	curve_params := e.Curve.Params()

	v, err := RandomScalar(random, curve_params.N)
	if err != nil {
		return nil, nil, nil, err
	}

	// Vx, Vy - encryption key
	Vx, Vy = e.Curve.ScalarBaseMult(v.Bytes())

	// Sx, Sy - shared secret
	Sx, _ := e.Curve.ScalarMult(e.X, e.Y, v.Bytes())

	// Encrypt the payload with KDF-ed S as the encryption key. Pass
	// the ciphertext along with V to the recipient. Recipient can
	// generate S using V and their priv key, and then KDF(S), on
	// their own, to get encryption key and decrypt the ciphertext,
	// revealing encryption key for symmetric encryption later.

	plain = PadBuffer(plain, 8)
	key := e.KDF(Sx.Bytes(), kdf_params, hash)

	// Take only as many bytes from key as the key length (the hash
	// result might be bigger)
	encrypted, err := AESKeyWrap(key[:32], plain)

	return Vx, Vy, encrypted, nil
}

func (e *PrivateKey) DecryptShared(X, Y *big.Int) ([]byte, error) {
	Sx, _ := e.Curve.ScalarMult(X, Y, e.X.Bytes())
	return Sx.Bytes(), nil
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return err
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return err
			}
		}
	}

	return nil
}
