// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// +build !nacl,!js,!nocgo

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"crypto/rand"
	"math/big"
	"errors"
	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrInvalidMsgLen       = errors.New("invalid message length, need 32 bytes")
	ErrInvalidSignatureLen = errors.New("invalid signature length")
	ErrInvalidRecoveryID   = errors.New("invalid signature recovery id")
	ErrInvalidKey          = errors.New("invalid private key")
)

// Ecrecover returns the uncompressed public key that created the given signature.
func Ecrecover(hash, sig []byte) ([]byte, error) {
	//return secp256k1.RecoverPubkey(hash, sig)
	//ecRecovery2(messageHash []byte, sig []byte,recId int64) (*ecdsa.PublicKey, error)
	if len(hash) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if err := checkSignature(sig); err != nil {
		return nil, err
	}
	recId := int64(sig[len(sig)-1])
	pubKey, err := ecRecovery2(hash, sig[:len(sig)-1],recId)
	if pubKey == nil {
		return nil, err
	}
	bk := elliptic.Marshal(S256(),pubKey.X,pubKey.Y)
	return bk,nil

}

// SigToPub returns the public key that created the given signature.
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	if len(hash) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if err := checkSignature(sig); err != nil {
		return nil, err
	}
	recId := int64(sig[len(sig)-1])
	pubKey, err := ecRecovery2(hash, sig[:len(sig)-1],recId)
	return pubKey,err
}

func checkSignature(sig []byte) error {
	if len(sig) != 65 {
		return ErrInvalidSignatureLen
	}
	if sig[64] >= 4 {
		return ErrInvalidRecoveryID
	}
	return nil
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
func decompressPubkey2(x *big.Int, yBit byte) (*ecdsa.PublicKey, error) {
	if (yBit != 0x02) && (yBit != 0x03) {
		return nil, fmt.Errorf("invalid yBit")
	}
	if x == nil {
		return nil, fmt.Errorf("invalid x")
	}

	xx := new(big.Int).Mul(x, x)
	xxa := new(big.Int).Sub(xx, big.NewInt(3))
	yy := new(big.Int).Mul(xxa, x)
	yy.Add(yy,elliptic.P256().Params().B)
	yy.Mod(yy,elliptic.P256().Params().P)

	y1 := new(big.Int).ModSqrt(yy,elliptic.P256().Params().P)
	if y1 == nil {
		return nil, fmt.Errorf("can not revcovery public key")
	}

	getY2 := func(y1 *big.Int) *big.Int {
		y2 := new(big.Int).Neg(y1)
		y2.Mod(y2, elliptic.P256().Params().P)
		return y2
	}

	y := new(big.Int)

	if yBit == 0x02 {
		if y1.Bit(0) == 0 {
			y = y1
		} else {
			y = getY2(y1)
		}
	} else {
		if y1.Bit(0) == 1 {
			y = y1
		} else {
			y = getY2(y1)
		}
	}

	return &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()}, nil
}
func ecRecovery2(messageHash []byte, sig []byte,recId int64) (*ecdsa.PublicKey, error) {
	if recId < 0 || recId > 3 {
		return nil,fmt.Errorf("invalid value of v")
	}

	sigLen := len(sig)
	r := new(big.Int).SetBytes(sig[:(sigLen / 2)])
	s := new(big.Int).SetBytes(sig[(sigLen / 2):])
	if r.Cmp(secp256r1N) > 0 || s.Cmp(secp256r1N) > 0 {
		return nil,fmt.Errorf("r or s can not big then n")
	}

	p256 := elliptic.P256()
	n := p256.Params().N
	i := new(big.Int).SetInt64(recId/2)
	x := new(big.Int).Add(r,i.Mul(i,n))

	prime := p256.Params().P
	if x.Cmp(prime) > 0 {
		return nil, fmt.Errorf("x can not big then q")
	}
	yBit := byte(0x02)
	if recId % 2 == 0 {
		yBit = 0x02
	} else {
		yBit = 0x03
	}
	R, err := decompressPubkey2(x,yBit)
	if err != nil {
		return nil ,err
	}

	r1, r2 := p256.ScalarMult(R.X,R.Y,n.Bytes())
	zero := new(big.Int)
	if ! ((r1.Cmp(zero) == 0) && (r2.Cmp(zero) == 0)) {
		return nil,fmt.Errorf("nR != point at infinity")
	}

	e := new(big.Int).SetBytes(messageHash)
	eInv := new(big.Int).SetInt64(0)
	eInv.Sub(eInv,e)
	eInv.Mod(eInv,n)

	rInv := new(big.Int).Set(r)
	rInv.ModInverse(rInv,n)

	srInv := new(big.Int).Set(rInv)
	srInv.Mul(srInv,s)
	srInv.Mod(srInv,n)

	eInvrInv := new(big.Int).Mul(rInv,eInv)
	eInvrInv.Mod(eInvrInv,n)

	krx,kry := p256.ScalarMult(R.X,R.Y,srInv.Bytes())
	kgx,kgy := p256.ScalarBaseMult(eInvrInv.Bytes())
	kx,ky := p256.Add(krx,kry,kgx,kgy)
	rkey := ecdsa.PublicKey{Curve: p256,X:kx,Y:ky}
	return &rkey,nil

}

// Sign calculates an ECDSA signature.
//
// This function is susceptible to chosen plaintext attacks that can leak
// information about the private key that is used for signing. Callers must
// be aware that the given hash cannot be chosen by an adversery. Common
// solution is to hash any input before calculating the signature.
//
// The produced signature is in the [R || S || V] format where V is 0 or 1.
func Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	if prv == nil {
		return nil, ErrInvalidKey
	}
	//seckey := math.PaddedBigBytes(prv.D, prv.Params().BitSize/8)
	//defer zeroBytes(seckey)
	//return secp256k1.Sign(hash, seckey)

	// sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, prv, hash)
	if err != nil {
		return nil, err
	}
	if s.Cmp(secp256r1halfN) > 0 {
		s = new(big.Int).Sub(secp256r1N, s)
	}

	// encode the signature {R, S}
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	curveOrderByteSize := S256().Params().P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2+1)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)
	// TODO: fix v value.
	recId := byte(0)

	for recId = 0;recId < 4; recId++ {
		pk,_ := ecRecovery2(hash,signature[:len(signature)-1],int64(recId))
		if pk != nil && comparePublicKey(pk,&prv.PublicKey) == true {
			signature[len(signature)-1] = recId
			return signature,nil
		}
	}
	return nil,fmt.Errorf("could not construct a recoverable key. This should never happen")
}

func comparePublicKey(key1, key2 *ecdsa.PublicKey) bool {
	// TODO: compare curve
	x := key1.X.Cmp(key2.X)
	y := key2.Y.Cmp(key2.Y)
	if x == 0 && y == 0 {
		return true
	} else {
		return false
	}
}

// VerifySignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
func VerifySignature(pubkey, hash, signature []byte) bool {
	//return secp256k1.VerifySignature(pubkey, hash, signature)
	if len(hash) != 32 {
		log.Info("hash length error")
		return false
	}
	if len(signature) != 64 {
		log.Info("signature length error")
		return false
	}
	if len(pubkey) == 0 {
		log.Info("public key length")
		return false
	}

	curveOrderByteSize := S256().Params().P.BitLen() / 8
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	if len(pubkey) == 33 {
		publicKey, err := DecompressPubkey(pubkey)
		if err != nil {
			log.Info("decompress public key error")
			return false
		}
		return ecdsa.Verify(publicKey, hash, r, s)
	} else if (len(pubkey) == 65) && (pubkey[0] == 0x04) {
		x,y := elliptic.Unmarshal(S256(),pubkey)
		if x == nil || y ==nil {
			log.Info("public key value error")
			return false
		}
		publicKey := ecdsa.PublicKey{Curve:S256(),X:x,Y:y}
		return ecdsa.Verify(&publicKey, hash, r, s)
	} else {
		log.Info("public key header error")
		return false
	}
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	if len(pubkey) != 33 {
		return nil, fmt.Errorf("invalid pubkey length")
	}
	yBit := pubkey[0]
	x := new(big.Int)
	x.SetBytes(pubkey[1:])
	return decompressPubkey2(x, yBit)
}

// CompressPubkey encodes a public key to the 33-byte compressed format.
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	//return secp256k1.CompressPubkey(pubkey.X, pubkey.Y)
	// big.Int.Bytes() will need padding in the case of leading zero bytes
	if pubkey == nil {
		return nil
	}
	curveOrderByteSize := S256().Params().P.BitLen() / 8
	xBytes := pubkey.X.Bytes()
	ckey := make([]byte, curveOrderByteSize+1)
	if pubkey.Y.Bit(0) == 1 {
		ckey[0] = 0x03
	} else {
		ckey[0] = 0x02
	}
	copy(ckey[1+curveOrderByteSize-len(xBytes):], xBytes)
	return ckey
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return elliptic.P256()
}
