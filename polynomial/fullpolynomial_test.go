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

package polynomial

import (
	"testing"

	"github.com/Wondertan/ntru/params"
	"github.com/Wondertan/ntru/testvectors"
)

func coeffEquals(a, b []int16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRecenterModQ_0(t *testing.T) {
	aCoeffs := []int16{1, 2, 3, 4, 5, 6, 7, 8}
	a := NewFromCoeffs(aCoeffs)
	a.recenterModQ(4, 0)
	expectedCoeffs := []int16{1, 2, 3, 0, 1, 2, 3, 0}
	if !coeffEquals(a.P, expectedCoeffs) {
		t.Error("a.P != expectedCoeffs")
	}
}

func TestRecenterModQ_2(t *testing.T) {
	aCoeffs := []int16{1, 2, 3, 4, 5, 6, 7, 8}
	a := NewFromCoeffs(aCoeffs)
	a.recenterModQ(4, -2)
	expectedCoeffs := []int16{1, -2, -1, 0, 1, -2, -1, 0}
	if !coeffEquals(a.P, expectedCoeffs) {
		t.Error("a.P != expectedCoeffs")
	}
}

func TestBasicConvolution_x1(t *testing.T) {
	aCoeffs := []int16{1, 0, 1, 0}
	bCoeffs := []int16{1, 0, 0, 0} // f(x) = 1
	p := Convolution(NewFromCoeffs(aCoeffs), NewFromCoeffs(bCoeffs))
	if !coeffEquals(aCoeffs, p.P) {
		t.Error("aCoeffs != p.P")
	}
}

func TestBasicConvolution_xX(t *testing.T) {
	aCoeffs := []int16{1, 0, 1, 0}
	bCoeffs := []int16{0, 1, 0, 0} // f(x) = x
	expectedCoeffs := []int16{0, 1, 0, 1}
	p := Convolution(NewFromCoeffs(aCoeffs), NewFromCoeffs(bCoeffs))
	if !coeffEquals(expectedCoeffs, p.P) {
		t.Error("expectedCoeffs != p.P")
	}
}

func TestBasicConvolution_3x_2x2(t *testing.T) {
	aCoeffs := []int16{10, 0, 5, 0}
	bCoeffs := []int16{0, 3, 2, 0} // f(x) = 3x + 2x^2
	expectedCoeffs := []int16{10, 30, 20, 15}
	p := Convolution(NewFromCoeffs(aCoeffs), NewFromCoeffs(bCoeffs))
	if !coeffEquals(expectedCoeffs, p.P) {
		t.Error("expectedCoeffs != p.P")
	}
}

func TestConvolution(t *testing.T) {
	for oid, vector := range testvectors.TestVectors {
		p := params.Param(oid)
		r := NewFromCoeffs(vector.Rr)
		h := NewFromCoeffs(vector.H)
		R := NewFromCoeffs(vector.R)
		out := ConvolutionModN(r, h, int(p.Q))
		if !out.Equals(R) {
			t.Errorf("[%d]: ConvolutionModN(r, h, q) != R", oid)
		}
	}
}

func TestAdd(t *testing.T) {
	for oid, vector := range testvectors.TestVectors {
		p := params.Param(oid)
		R := NewFromCoeffs(vector.R)
		mP := NewFromCoeffs(vector.MPrime)
		e := NewFromCoeffs(vector.E)
		out := R.Add(mP, int(p.Q))
		if !out.Equals(e) {
			t.Errorf("[%d]: R.Add(mP, q) != e", oid)
		}
	}
}

func TestAddAndRecenter(t *testing.T) {
	for oid, vector := range testvectors.TestVectors {
		// m' = mask + Mtrin (mod p)
		p := params.Param(oid)
		mask := NewFromCoeffs(vector.Mask)
		Mtrin := NewFromCoeffs(vector.Mtrin)
		mP := NewFromCoeffs(vector.MPrime)
		out := mask.AddAndRecenter(Mtrin, int(p.P), -1)
		if !out.Equals(mP) {
			t.Errorf("[%d]: mask.AddAndRecenter(Mtrin, p, -1) != mP", oid)
		}
	}
}

func TestSubtract(t *testing.T) {
	for oid, vector := range testvectors.TestVectors {
		p := params.Param(oid)
		R := NewFromCoeffs(vector.R)
		mP := NewFromCoeffs(vector.MPrime)
		e := NewFromCoeffs(vector.E)
		out := e.Subtract(mP, int(p.Q))
		if !out.Equals(R) {
			t.Errorf("[%d]: e.Subtract(mP, q) != R", oid)
		}
	}
}

func TestSubtractAndRecenter(t *testing.T) {
	for oid, vector := range testvectors.TestVectors {
		// m' = mask + Mtrin (mod p)
		p := params.Param(oid)
		mask := NewFromCoeffs(vector.Mask)
		Mtrin := NewFromCoeffs(vector.Mtrin)
		mP := NewFromCoeffs(vector.MPrime)
		out := mP.SubtractAndRecenter(mask, int(p.P), -1)
		if !out.Equals(Mtrin) {
			t.Errorf("[%d]: mP.AddAndRecenter(mask, p, -1) != Mtrin", oid)
		}
	}
}

func TestEquals(t *testing.T) {
	aCoeffs := []int16{0, 1, 2, 3, 4, 5}
	bCoeffs := []int16{0, 1, 2, 3, 4, 5}
	a := NewFromCoeffs(aCoeffs)
	b := NewFromCoeffs(bCoeffs)
	if !a.Equals(b) {
		t.Error("a != b")
	}

	b.P[0]++
	if a.Equals(b) {
		t.Error("a == b")
	}
}
