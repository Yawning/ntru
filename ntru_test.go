/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * Copyright (C) 2014  Yawning Angel (yawning at schwanenlied dot me)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *********************************************************************************/

package ntru

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"testing"

	"github.com/yawning/ntru/params"
	"github.com/yawning/ntru/polynomial"
	"github.com/yawning/ntru/testvectors"
)

// hashDrbg is a Hash_DRBG using SHA256.  It is included here because it is the
// entropy source (with a known seed) used for key generation, and should not
// be used for anything apart from testing.
type hashDrbg struct {
	mHash hash.Hash
	v     []byte
	c     []byte
	ctr   uint32
}

func newHashDrbg(seed []byte) (h *hashDrbg) {
	t := []byte{
		0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8,
		0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
		0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b,
		0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
		0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1,
		0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
		0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63,
		0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
		0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda,
		0x3e,
	}

	h = &hashDrbg{mHash: sha256.New(), ctr: 1}
	if len(seed) != h.mHash.Size() {
		panic("drbg: invalid seed length")
	}
	h.v = make([]byte, len(seed))
	copy(h.v, seed)
	h.mHash.Write(t[:h.mHash.Size()])
	h.mHash.Write(h.v)
	h.c = h.mHash.Sum(nil)
	h.mHash.Reset()

	return
}

func (h *hashDrbg) Read(out []byte) (int, error) {
	h.hashGen(out)

	suffixLen := len(out)
	if suffixLen > len(h.v) {
		suffixLen = len(h.v)
	}

	h.plusEquals(h.c)
	h.plusEquals(out[:suffixLen])
	h.plusEqualsUint32(h.v, h.ctr)
	h.ctr++

	return len(out), nil
}

func (h *hashDrbg) ReadByte() (c byte, err error) {
	var tmp [1]byte
	_, err = h.Read(tmp[:])
	if err != nil {
		return 0, err
	}
	c = tmp[0]
	return
}

func (h *hashDrbg) hashGen(out []byte) {
	// offset is always 0 for us.
	offset := 0
	l := len(out)

	hLen := h.mHash.Size()
	vtmp := make([]byte, hLen)
	copy(vtmp, h.v)
	for l > hLen {
		h.mHash.Write(vtmp)
		stmp := h.mHash.Sum(nil)
		h.mHash.Reset()
		copy(out[offset:], stmp)
		offset += hLen
		l -= hLen
		h.plusEqualsUint32(vtmp, 1)
	}

	h.mHash.Write(vtmp)
	stmp := h.mHash.Sum(nil)
	h.mHash.Reset()
	copy(out[offset:], stmp)
}

func (h *hashDrbg) plusEqualsUint32(dst []byte, i uint32) {
	dstLen := len(dst)
	tmp := binary.BigEndian.Uint32(dst[dstLen-4 : dstLen])
	tmp += i
	binary.BigEndian.PutUint32(dst[dstLen-4:dstLen], tmp)
}

func (h *hashDrbg) plusEquals(src []byte) {
	carry := 0
	i, j := len(src)-1, len(h.v)-1
	for i >= 0 && j >= 0 {
		carry += int(h.v[j]) + int(src[i])
		h.v[j] = byte(carry)
		carry >>= 8
		j--
		i--
	}
}

func TestHashDrbg(t *testing.T) {
	seed := []byte{
		0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
		0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
		0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
		0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51,
	}
	drbg := newHashDrbg(seed)
	n := make([]byte, 80)

	ans_1 := []byte{
		0x1a, 0xbf, 0x2e, 0xb1, 0xcb, 0x32, 0xa8, 0xf5,
		0xfb, 0x4b, 0xdd, 0xef, 0x8f, 0x70, 0xc6, 0x20,
		0xc7, 0x47, 0x7e, 0xd9, 0x7a, 0xab, 0xf5, 0x87,
		0x81, 0xd6, 0x82, 0xbc, 0xf3, 0xa2, 0x58, 0x71,
		0xa1, 0x7b, 0x37, 0xa4, 0xa4, 0x5b, 0x17, 0xcd,
		0x4b, 0xb5, 0x5b, 0x2e, 0x95, 0xc0, 0xb4, 0xbc,
		0xda, 0xbc, 0x50, 0xd0, 0x0f, 0x38, 0x08, 0x87,
		0x0d, 0xfe, 0x7a, 0x96, 0x02, 0x70, 0x79, 0x1e,
		0x89, 0xff, 0x93, 0xb6, 0x0f, 0x21, 0xcc, 0x27,
		0xf1, 0xcc, 0x48, 0xd0, 0xc8, 0x6f, 0x49, 0xd1,
	}
	drbg.Read(n)
	if bytes.Compare(ans_1, n) != 0 {
		t.Errorf("ans_1 != n")
	}

	ans_2 := []byte{
		0x3f, 0x3a, 0xdd, 0x70, 0x14, 0xbd, 0x71, 0x90,
		0xf1, 0x75, 0x5b, 0xe2, 0x25, 0x99, 0xb6, 0xc9,
		0xc9, 0x01, 0x95, 0xbe, 0x27, 0x48, 0x71, 0x0b,
		0x8b, 0x9e, 0xd4, 0x87, 0x36, 0x8f, 0xe7, 0x58,
		0x38, 0xe4, 0x40, 0xb3, 0x99, 0x85, 0x03, 0x9a,
		0x21, 0xda, 0x07, 0xee, 0xdf, 0xdc, 0x6f, 0xa9,
		0x7f, 0x2a, 0xf6, 0x93, 0x2d, 0x11, 0x9a, 0x6b,
		0x1f, 0x2a, 0xff, 0xac, 0x7e, 0x14, 0xa8, 0x1b,
		0x3c, 0x8a, 0x4f, 0xb1, 0x07, 0x98, 0xe4, 0x94,
		0x06, 0xf3, 0x68, 0xa3, 0x41, 0xfa, 0x0c, 0xd3,
	}
	drbg.Read(n)
	if bytes.Compare(ans_2, n) != 0 {
		t.Errorf("ans_2 != n")
	}
}

func TestGenerateM(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		rng := bytes.NewBuffer(vec.B)
		pub := PublicKey{Params: params.Param(oid)}
		m, err := pub.generateM(vec.M, rng)
		if err != nil {
			t.Error(err)
		}
		if bytes.Compare(vec.Mbin, m) != 0 {
			t.Errorf("[%d]: vec.Mbin != m", oid)
		}
	}
}

func TestFormSData(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		pub := PublicKey{Params: params.Param(oid)}
		pub.H = polynomial.NewFromCoeffs(vec.H)
		sData := pub.formSData(vec.M, 0, len(vec.M), vec.B, 0)
		if bytes.Compare(vec.SData, sData) != 0 {
			t.Errorf("[%d]: vec.SData != sData", oid)
		}
	}
}

func TestFormSDataEmbedded(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		pub := PublicKey{Params: params.Param(oid)}
		pub.H = polynomial.NewFromCoeffs(vec.H)

		data := make([]byte, len(vec.M)+len(vec.B)+92)
		for i := range data {
			data[i] = 23
		}
		mOffset := 33
		bOffset := 72
		copy(data[mOffset:], vec.M)
		copy(data[bOffset:], vec.B)
		sData := pub.formSData(data, mOffset, len(vec.M), data, bOffset)
		if bytes.Compare(vec.SData, sData) != 0 {
			t.Errorf("[%d]: vec.SData != sData", oid)
		}
	}
}

func TestConvPolyBinaryToTrinaryHelper(t *testing.T) {
	out := make([]int16, 16)
	for i := range out {
		out[i] = 22
	}

	convPolyBinaryToTrinaryHelper(len(out), 0, out, 7)
	convPolyBinaryToTrinaryHelper(len(out), 2, out, 6)
	convPolyBinaryToTrinaryHelper(len(out), 4, out, 5)
	convPolyBinaryToTrinaryHelper(len(out), 6, out, 4)
	convPolyBinaryToTrinaryHelper(len(out), 8, out, 3)
	convPolyBinaryToTrinaryHelper(len(out), 10, out, 2)
	convPolyBinaryToTrinaryHelper(len(out), 12, out, 1)
	convPolyBinaryToTrinaryHelper(len(out), 14, out, 0)

	expectedOut := []int16{
		-1, 1, -1, 0, 1, -1, 1, 1, 1, 0, 0, -1, 0, 1, 0, 0,
	}
	if !testvectors.ArrayEquals(out, expectedOut) {
		t.Error("out != expectedOut")
	}
}

func TestConvPolyBinaryToTrinaryHelper2(t *testing.T) {
	out := make([]int16, 19)
	for i := range out {
		out[i] = 22
	}
	convPolyBinaryToTrinaryHelper2(len(out), 3, out, 0x00e1e83a)
	expectedOut := []int16{
		22, 22, 22,
		-1, 1, 0, 0, 1, 0, -1, 0, 1, 1, 0, 0, -1, 1, 0, -1,
	}
	if !testvectors.ArrayEquals(out, expectedOut) {
		t.Error("a: out != expectedOut")
	}

	out = out[:16]
	for i := range out {
		out[i] = 22
	}
	convPolyBinaryToTrinaryHelper2(len(out), 0, out, 0x00c8a669)
	expectedOut = []int16{
		-1, 0, 0, -1, 0, 1, 0, -1, 1, 0, 0, 1, 1, -1, 0, 1,
	}
	if !testvectors.ArrayEquals(out, expectedOut) {
		t.Error("b: out != expectedOut")
	}
}

func TestConvPolyBinaryToTrinary(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		keyParams := params.Param(oid)
		out := convPolyBinaryToTrinary(int(keyParams.N), vec.Mbin)
		if !testvectors.ArrayEquals(out, vec.Mtrin) {
			t.Errorf("[%d]: out != vec.Mtrin", oid)
		}
	}
}

func TestConvPolyTritToBitHelper(t *testing.T) {
	vec := []struct {
		exp    byte
		t1, t2 int16
	}{
		{0, 0, 0},
		{1, 0, 1},
		{2, 0, -1},
		{3, 1, 0},
		{4, 1, 1},
		{5, 1, -1},
		{6, -1, 0},
		{7, -1, 1},
		{0xff, -1, -1},
	}

	for _, v := range vec {
		b := convPolyTritToBitHelper(v.t1, v.t2)
		if v.exp != b {
			t.Errorf("convPoltTritToBitHelper(%d, %d) != %x (got: %x)", v.t1, v.t2, v.exp, b)
		}
	}
}

func TestConvPolyTrinaryToBinaryBlockHelper(t *testing.T) {
	trits := []int16{
		1, -1, 0, 0, -1, 1, 1, 1,
		0, 0, 1, 0, 0, 1, 1, 1,
	}
	exp := []byte{0xa3, 0xc0, 0xcc}
	bits := make([]byte, 3)
	convPolyTrinaryToBinaryBlockHelper(0, trits, 0, bits)
	if bytes.Compare(exp, bits) != 0 {
		t.Error("exp != bits")
	}

	// withOffset()
	trits = []int16{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		1, -1, 0, 0, -1, 1, 1, 1,
		0, 0, 1, 0, 0, 1, 1, 1,
	}
	exp = []byte{22, 22, 22, 0xa3, 0xc0, 0xcc}
	bits = make([]byte, 6)
	for i := range bits {
		bits[i] = 22
	}
	convPolyTrinaryToBinaryBlockHelper(16, trits, 3, bits)
	if bytes.Compare(exp, bits) != 0 {
		t.Error("exp != bits")
	}

	// withOffset_truncate()
	exp = exp[:5]
	bits = bits[:5]
	for i := range bits {
		bits[i] = 22
	}
	convPolyTrinaryToBinaryBlockHelper(16, trits, 3, bits)
	if bytes.Compare(exp, bits) != 0 {
		t.Error("exp != bits")
	}

	// withOffset_short_inbuf()
	trits = []int16{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 1, 1, 1,
		1, -1, 0, 0, -1, // Missing last 11 trits.
	}
	exp = []byte{22, 22, 22, 0xa3, 0x00, 0x00}
	bits = make([]byte, 6)
	for i := range bits {
		bits[i] = 22
	}
	convPolyTrinaryToBinaryBlockHelper(24, trits, 3, bits)
	if bytes.Compare(exp, bits) != 0 {
		t.Error("exp != bits")
	}
}

func TestConvPolyTrinaryToBinary(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		pub := PublicKey{Params: params.Param(oid)}
		Mtrin := polynomial.NewFromCoeffs(vec.Mtrin)
		out := pub.convPolyTrinaryToBinary(Mtrin)
		if bytes.Compare(out, vec.Mbin) != 0 {
			t.Errorf("[%d]: out != vec.Mbin", oid)
		}
	}
}

func TestCalcPolyMod4Packed(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		r := polynomial.NewFromCoeffs(vec.R)
		out := calcPolyMod4Packed(r)
		if bytes.Compare(out, vec.R4) != 0 {
			t.Errorf("[%d]: out != vec.R4", oid)
		}
	}
}

func TestCalcEncryptionMask(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		pub := PublicKey{Params: params.Param(oid)}
		r := polynomial.NewFromCoeffs(vec.R)
		out := pub.calcEncryptionMask(r)
		if !testvectors.ArrayEquals(out.P, vec.Mask) {
			t.Errorf("[%d]: out.P != vec.Mask", oid)
		}
	}
}

func TestCheckDm0(t *testing.T) {
	threeOnesArray := []int16{-1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 1}
	threeOnes := polynomial.NewFromCoeffs(threeOnesArray)
	if checkDm0(threeOnes, 4) {
		t.Errorf("checkDm0(threeOnes, 4) != false")
	}
	if !checkDm0(threeOnes, 3) {
		t.Errorf("checkDm0(threeOnes, 3) != true")
	}
	if !checkDm0(threeOnes, 2) {
		t.Errorf("checkDm0(threeOnes, 2) != true")
	}

	threeZerosArray := []int16{-1, -1, -1, -1, -1, 0, 0, 0, 1, 1, 1, 1, 1}
	threeZeros := polynomial.NewFromCoeffs(threeZerosArray)
	if checkDm0(threeZeros, 4) {
		t.Errorf("checkDm0(threeZeros, 4) != false")
	}
	if !checkDm0(threeZeros, 3) {
		t.Errorf("checkDm0(threeZeros, 3) != true")
	}
	if !checkDm0(threeZeros, 2) {
		t.Errorf("checkDm0(threeZeros, 2) != true")
	}

	threeNegOnesArray := []int16{-1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 1, 1, 1}
	threeNegOnes := polynomial.NewFromCoeffs(threeNegOnesArray)
	if checkDm0(threeNegOnes, 4) {
		t.Errorf("checkDm0(threeNegOnes, 4) != false")
	}
	if !checkDm0(threeNegOnes, 3) {
		t.Errorf("checkDm0(threeNegOnes, 3) != true")
	}
	if !checkDm0(threeNegOnes, 2) {
		t.Errorf("checkDm0(threeNegOnes, 2) != true")
	}
}

func TestParseMsgLengthFromM(t *testing.T) {
	for oid := range testvectors.TestVectors {
		priv := &PrivateKey{}
		priv.Params = params.Param(oid)

		// short_buffer()
		m := make([]byte, priv.Params.Db/8-1)
		if priv.parseMsgLengthFromM(m) != 0 {
			t.Errorf("[%d]: short: parseMsgLengthFromM(m) != 0", oid)
		}

		// Positive case.
		m = make([]byte, priv.Params.N)
		for i := 0; i < 12; i++ {
			m[priv.Params.Db/8] = byte(i)
			tmp := priv.parseMsgLengthFromM(m)
			if tmp != i {
				t.Errorf("[%d]: parseMsgLengthFromM(m[:%d]) != %d (got: %d)", oid, i, i, tmp)
			}
		}
	}
}

func TestVerifyMFormat(t *testing.T) {
	priv := &PrivateKey{}
	priv.Params = params.Param(params.EES401EP1)

	// shortInputBuffer()
	m := make([]byte, priv.Params.N-2)
	m[priv.Params.Db/8] = 1
	if priv.verifyMFormat(m) != -1 {
		t.Errorf("shortInputBuffer != -1")
	}

	// invalidMLen()
	m = make([]byte, priv.Params.N)
	m[priv.Params.Db/8] = 0xff
	if priv.verifyMFormat(m) != -1 {
		t.Errorf("invalidMLen != -1")
	}

	// invalidp0()
	m[priv.Params.Db/8] = 1
	m[priv.Params.Db/8+priv.Params.LLen+1+1] = 2
	if priv.verifyMFormat(m) != -1 {
		t.Errorf("invalidp0 != -1")
	}

	// Postitive case.
	for oid := range testvectors.TestVectors {
		priv = &PrivateKey{}
		priv.Params = params.Param(oid)

		m = make([]byte, priv.Params.Db/8+priv.Params.LLen+int16(priv.Params.MaxMsgLenBytes)+1)
		m[priv.Params.Db/8] = 1
		m[priv.Params.Db/8+priv.Params.LLen] = 22
		if 1 != priv.verifyMFormat(m) {
			t.Errorf("[%d]: verifyMFormat(m) != 1", oid)
		}
	}
}

func TestPublicKeySerialize(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		pub := &PublicKey{Params: params.Param(oid)}
		pub.H = polynomial.NewFromCoeffs(vec.H)

		// Hand-craft the expected blob based on the test vectors.
		exp := make([]byte, 0, 4+len(vec.PackedH))
		exp = append(exp, blobPublicKeyV1)
		exp = append(exp, vec.OIDBytes...)
		exp = append(exp, vec.PackedH...)

		// Test encode.
		blob := pub.Bytes()
		if bytes.Compare(exp, blob) != 0 {
			t.Errorf("[%d]: encode: exp != blob", oid)
		}

		// Test decode.
		h, err := NewPublicKey(exp)
		if err != nil {
			t.Error(err)
		}
		if h.Params != pub.Params || !testvectors.ArrayEquals(vec.H, h.H.P) {
			t.Errorf("[%d]: decode: h!= priv", oid)
		}
	}
}

func TestPrivateKeySerialize(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		priv := &PrivateKey{}
		priv.Params = params.Param(oid)
		priv.H = polynomial.NewFromCoeffs(vec.H)
		priv.F = polynomial.NewFromCoeffs(vec.Ff)

		// Hand-craft the expected blob based on the test vectors.
		var exp []byte
		if len(vec.PackedF) < len(vec.PackedListedF) {
			exp = make([]byte, 0, 4+len(vec.PackedH)+len(vec.PackedF))
			exp = append(exp, blobPrivateKeyDefaultV1)
			exp = append(exp, vec.OIDBytes...)
			exp = append(exp, vec.PackedH...)
			exp = append(exp, vec.PackedF...)
		} else {
			exp = make([]byte, 0, 4+len(vec.PackedH)+len(vec.PackedListedF))
			exp = append(exp, blobPrivateKeyDefaultV1)
			exp = append(exp, vec.OIDBytes...)
			exp = append(exp, vec.PackedH...)
			exp = append(exp, vec.PackedListedF...)
		}

		// Test encode.
		blob := priv.Bytes()
		if bytes.Compare(exp, blob) != 0 {
			t.Errorf("[%d]: encode: exp != blob", oid)
		}

		// Test decode.
		f, err := NewPrivateKey(exp)
		if err != nil {
			t.Error(err)
		}
		if f.Params != priv.Params || !testvectors.ArrayEquals(vec.H, f.H.P) {
			t.Errorf("[%d]: decode: f != priv(pub)", oid)
		}
		if !testvectors.ArrayEquals(vec.Ff, f.F.P) {
			t.Errorf("[%d]: decode: f != priv", oid)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		priv := &PrivateKey{}
		priv.Params = params.Param(oid)
		priv.H = polynomial.NewFromCoeffs(vec.H)
		priv.F = polynomial.NewFromCoeffs(vec.Ff)

		rng := newHashDrbg(vec.KeygenSeed)
		genPriv, err := GenerateKey(rng, oid)
		if err != nil {
			t.Fatal(err)
		}

		if genPriv.Params != priv.Params {
			t.Errorf("[%d]: GenerateKey param mismatch", oid)
		}
		if !testvectors.ArrayEquals(vec.H, genPriv.H.P) {
			t.Errorf("[%d]: GenerateKey H mismatch", oid)
		}
		if !testvectors.ArrayEquals(vec.Ff, genPriv.F.P) {
			t.Errorf("[%d]: GenerateKey F mismatch", oid)
		}
	}
}

func TestEncrypt(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		pub := &PublicKey{Params: params.Param(oid)}
		pub.H = polynomial.NewFromCoeffs(vec.H)

		prng := bytes.NewBuffer(vec.B)
		ct, err := Encrypt(prng, pub, vec.M)
		if err != nil {
			t.Errorf("[%d]: Encrypt(prng, pub, vec.M) failed: %v", oid, err)
		}
		if bytes.Compare(ct, vec.PackedE) != 0 {
			t.Errorf("[%d]: ct != vec.PackedE", oid)
		}
	}
}

func TestDecrypt(t *testing.T) {
	for oid, vec := range testvectors.TestVectors {
		priv := &PrivateKey{}
		priv.Params = params.Param(oid)
		priv.H = polynomial.NewFromCoeffs(vec.H)
		priv.F = polynomial.NewFromCoeffs(vec.Ff)

		out, err := Decrypt(priv, vec.PackedE)
		if err != nil {
			t.Errorf("[%d]: Decrypt(priv, vec.PackedE) failed: %v", oid, err)
		}
		if bytes.Compare(out, vec.M) != 0 {
			t.Errorf("[%d]: out != vec.M", oid)
		}
	}
}

func TestIntegration(t *testing.T) {
	keypair, err := GenerateKey(rand.Reader, params.EES1171EP1)
	if err != nil {
		t.Fatal(err)
	}

	blen := keypair.Params.MaxMsgLenBytes
	plaintext := make([]byte, blen)
	rand.Reader.Read(plaintext)

	ciphertext, err := Encrypt(rand.Reader, &keypair.PublicKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	plaintext2, err := Decrypt(keypair, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(plaintext, plaintext2) != 0 {
		t.Fatal("plaintext != plaintext2")
	}
}

func BenchmarkGenerateKey_EES1171EP1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey(rand.Reader, params.EES1171EP1)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkEncrypt_EES1171EP1(b *testing.B) {
	priv, err := GenerateKey(rand.Reader, params.EES1171EP1)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, priv.Params.MaxMsgLenBytes)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt_EES1171EP1(b *testing.B) {
	priv, err := GenerateKey(rand.Reader, params.EES1171EP1)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, priv.Params.MaxMsgLenBytes)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, plaintext)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(priv, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
