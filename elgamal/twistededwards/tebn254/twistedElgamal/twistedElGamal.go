package twistedElgamal

import (
	"math/big"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
)

var (
	// Order of the group
	Order = curve.Order
	// base point
	G = curve.G
	// base point generated by seed
	H = curve.H
)

type Point = curve.Point

type ElGamalEnc struct {
	CL *Point // pk^r
	CR *Point // g^r h^b
}

/**
Add encryption entities
@C1: Encryption entity 1
@C2: Encryption entity 2
*/
func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) (*ElGamalEnc, error) {
	if C1 == nil || C2 == nil {
		return nil, ErrParams
	}
	CL := curve.Add(C1.CL, C2.CL)
	CR := curve.Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}, nil
}

/**
sub encryption entities
@C1: Encryption entity 1
@C2: Encryption entity 2
*/
func EncSub(C1 *ElGamalEnc, C2 *ElGamalEnc) (*ElGamalEnc, error) {
	if C1 == nil || C2 == nil {
		return nil, ErrParams
	}
	CL := curve.Add(C1.CL, curve.Neg(C2.CL))
	CR := curve.Add(C1.CR, curve.Neg(C2.CR))
	return &ElGamalEnc{CL: CL, CR: CR}, nil
}

/**
Generate key pair, sk \gets_R mathbb{Z}_p, pk = g^{sk}
*/
func GenKeyPair() (sk *big.Int, pk *Point) {
	sk = curve.RandomValue()
	pk = curve.ScalarBaseMul(sk)
	return sk, pk
}

/**
Set value into the ElGamalEnc
*/
func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(Point).Set(enc.CL)
	value.CR = new(Point).Set(enc.CR)
}

/**
Get public key of the secret key
@sk: secret key
*/
func Pk(sk *big.Int) (pk *Point) {
	pk = curve.ScalarBaseMul(sk)
	return pk
}

/**
Encryption method: C_L = pk^r, C_R = g^r h^b
@b: the amount needs to be encrypted
@r: the random value
@pk: public key
*/
func Enc(b *big.Int, r *big.Int, pk *Point) (*ElGamalEnc, error) {
	if b == nil || r == nil || pk == nil || !curve.IsInSubGroup(pk) {
		return nil, ErrParams
	}
	// pk^r
	CL := curve.ScalarMul(pk, r)
	// g^r h^b
	CR, _ := pedersen.Commit(r, b, G, H)
	return &ElGamalEnc{CL: CL, CR: CR}, nil
}

/**
Decrypt Method: h^b = C_R / (C_L)^{sk^{-1}}, then compute b by brute-force
@enc: encryption entity
@sk: the private key of the encryption public key
@Max: the max size of b
*/
func Dec(enc *ElGamalEnc, sk *big.Int, Max int64) (*big.Int, error) {
	if enc == nil || enc.CL == nil || enc.CR == nil || sk == nil || Max < 0 {
		return nil, ErrParams
	}
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, Order)
	gExpr := curve.ScalarMul(enc.CL, skInv)
	hExpb := curve.Add(enc.CR, curve.Neg(gExpr))

	base := H
	current := curve.ZeroPoint()
	for i := int64(0); i < Max; i++ {
		if current.Equal(hExpb) {
			return big.NewInt(i), nil
		}
		current.Add(current, base)
	}
	return nil, ErrDec
}

/**
Decrypt Method: h^b = C_R / (C_L)^{sk^{-1}}, then compute b by brute-force, start at some value
@enc: encryption entity
@sk: the private key of the encryption public key
@start: the start value
@Max: the max size of b
*/
func DecByStart(enc *ElGamalEnc, sk *big.Int, start int64, Max int64) (*big.Int, error) {
	if enc == nil || enc.CL == nil || enc.CR == nil ||
		sk == nil || start < 0 || Max < 0 || start < Max {
		return nil, ErrParams
	}
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, Order)
	gExpr := curve.ScalarMul(enc.CL, skInv)
	hExpb := curve.Add(enc.CR, curve.Neg(gExpr))
	base := H
	current := curve.ZeroPoint()
	for i := int64(start); i < Max; i++ {
		if current.Equal(hExpb) {
			return big.NewInt(i), nil
		}
		current.Add(current, base)
	}
	return nil, ErrDec
}
