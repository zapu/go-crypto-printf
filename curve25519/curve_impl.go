package curve25519

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var cv25519 cv25519Curve

type cv25519Curve struct {
	*elliptic.CurveParams
}

func copy_reverse(dst []byte, src []byte) {
	// Curve 25519 multiplication functions expect scalars in reverse
	// order than PGP. To keep the curve25519Curve type consistent
	// with other curves, we reverse it here.
	for i, j := 0, len(src)-1; j >= 0; i, j = i+1, j-1 {
		dst[i] = src[j]
	}
}

func (cv25519Curve) ScalarMult(x1, y1 *big.Int, scalar []byte) (x, y *big.Int) {
	// Assume y1 is 0 with cv25519.
	var dst [32]byte
	var x1_bytes [32]byte
	var scalar_bytes [32]byte

	copy(x1_bytes[:], x1.Bytes()[:32])
	copy_reverse(scalar_bytes[:], scalar[:32])

	scalarMult(&dst, &scalar_bytes, &x1_bytes)

	x = new(big.Int).SetBytes(dst[:])
	y = new(big.Int)
	return x, y
}

func (cv25519Curve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	var dst [32]byte
	var scalar_bytes [32]byte
	copy_reverse(scalar_bytes[:], scalar[:32])
	scalarMult(&dst, &scalar_bytes, &basePoint)
	x = new(big.Int).SetBytes(dst[:])
	y = new(big.Int)
	return x, y
}

func (cv25519Curve) IsOnCurve(bigX, bigY *big.Int) bool {
	return true
}

func (cv25519Curve) MarshalType40(x, y *big.Int) []byte {
	byteLen := 32

	ret := make([]byte, 1+byteLen)
	ret[0] = 0x40

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	return ret
}

func (cv25519Curve) UnmarshalType40(data []byte) (x, y *big.Int) {
	if len(data) != 1+32 {
		return
	}
	if data[0] != 0x40 {
		return
	}
	x = new(big.Int).SetBytes(data[1:])
	return x, nil
}

// elliptic.Marshal and elliptic.Unmarshal only marshals uncompressed
// 0x4 MPI types. These functions will check if the curve is cv25519,
// and if so, use 0x40 compressed type to (un)marshal. Otherwise,
// elliptic.(Un)marshal will be called.

func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	cv, ok := curve.(cv25519Curve)
	if !ok {
		return elliptic.Marshal(curve, x, y)
	} else {
		return cv.MarshalType40(x, y)
	}
}

func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	cv, ok := curve.(cv25519Curve)
	if !ok {
		return elliptic.Unmarshal(curve, data)
	} else {
		return cv.UnmarshalType40(data)
	}
}

func initCv25519() {
	cv25519.CurveParams = &elliptic.CurveParams{Name: "Curve 25519"}
	cv25519.P, _ = new (big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	cv25519.N, _ = new (big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	cv25519.Gx, _ = new (big.Int).SetString("9", 16)
	cv25519.Gy, _ = new (big.Int).SetString("20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9", 16)
	cv25519.BitSize = 256
}

var initonce sync.Once

func Cv25519() elliptic.Curve {
	initonce.Do(initCv25519)
	return cv25519
}

func (curve cv25519Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}
