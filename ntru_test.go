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
	"testing"

	"github.com/yawning/ntru/params"
	"github.com/yawning/ntru/polynomial"
	"github.com/yawning/ntru/testvectors"

	"fmt"
)

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

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey(rand.Reader, params.EES1171EP1)
	if err != nil {
		t.Error(err)
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
		exp := make([]byte, 0, 4+len(vec.PackedH)+len(vec.PackedF))
		exp = append(exp, blobPrivateKeyDefaultV1)
		exp = append(exp, vec.OIDBytes...)
		exp = append(exp, vec.PackedH...)
		exp = append(exp, vec.PackedF...)

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
			t.Fatalf("[%d]: decode: f != priv(pub)", oid)
		}
		if !testvectors.ArrayEquals(vec.Ff, f.F.P) {
			fmt.Printf("vecF: %v\n", vec.Ff)
			fmt.Printf("   F: %v\n", f.F.P)
			t.Fatalf("[%d]: decode: f != priv", oid)
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

func BenchmarkGenerateKey_EES1171EP1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateKey(rand.Reader, params.EES1171EP1)
		if err != nil {
			b.Error(err)
		}
	}
}
