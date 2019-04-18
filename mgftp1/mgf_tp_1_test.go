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

// Package mgftp1 implements the MGF-TP-1 algoritm for converting a byte stream
// into a sequence of trits.  It implements both the forward direction and the
// reverse.
package mgftp1

import (
	"bytes"
	"testing"

	"github.com/Wondertan/ntru/polynomial"
	"github.com/Wondertan/ntru/testvectors"
)

func TestDecodeSmall(t *testing.T) {
	input := []byte{48}
	output := []int16{0, 1, -1, 1, 0}
	r := bytes.NewBuffer(input)

	p, err := GenTrinomial(5, r)
	if err != nil {
		t.Error(err)
	}
	if !testvectors.ArrayEquals(output, p.P) {
		t.Error("output != p.P")
	}
}

func TestDecodeSkipInvalidInput(t *testing.T) {
	input := []byte{243, 244, 245, 255, 48}
	output := []int16{0, 1, -1, 1, 0}
	r := bytes.NewBuffer(input)

	p, err := GenTrinomial(5, r)
	if err != nil {
		t.Error(err)
	}
	if !testvectors.ArrayEquals(output, p.P) {
		t.Error("output != p.P")
	}
}

func TestDecodeMisalignedOutput(t *testing.T) {
	input := []byte{243, 244, 245, 255, 48, 4}
	output := []int16{0, 1, -1, 1, 0, 1, 1}
	r := bytes.NewBuffer(input)

	p, err := GenTrinomial(7, r)
	if err != nil {
		t.Error(err)
	}
	if !testvectors.ArrayEquals(output, p.P) {
		t.Error("output != p.P")
	}
}

func TestEncodeSmall(t *testing.T) {
	input := []int16{0, 1, -1, 1, 0}
	exp := []byte{48}
	p := polynomial.NewFromCoeffs(input)
	out := bytes.NewBuffer(nil)

	if err := EncodeTrinomial(p, out); err != nil {
		t.Error(err)
	}
	if bytes.Compare(out.Bytes(), exp) != 0 {
		t.Error("out != exp")
	}
}

func TestEncodeAlignedInput(t *testing.T) {
	input := []int16{
		1, 1, 1, 0, -1, 0, -1, -1, -1, 0, 0, 1, 0, 0, 1,
		0, 0, -1, 0, -1, 1, 0, 1, 0, 1, 0, -1, -1, -1, 0,
		-1, 1, 1, 0, 0, 0, -1, 0, 1, 0, 0, -1, -1, 0, 0,
		1, 0, 1, -1, 1, -1, 1, 1, 1, 0, 0, 1, 1, -1, -1,
		0, 1, 0, 0, 0,
	}
	exp := []byte{
		0xaf, 0x4e, 0x54, 0xb4, 0x5b, 0x4e, 0x0e, 0x21,
		0x18, 0x91, 0x29, 0xe4, 0x03,
	}
	p := polynomial.NewFromCoeffs(input)
	out := bytes.NewBuffer(nil)

	if err := EncodeTrinomial(p, out); err != nil {
		t.Error(err)
	}
	if bytes.Compare(out.Bytes(), exp) != 0 {
		t.Error("out != exp")
	}
}

func TestEncodeMisalignedInput(t *testing.T) {
	input := []int16{
		1, 1, 1, 0, -1, 0, -1, -1, -1, 0, 0, 1, 0, 0, 1,
		0, 0, -1, 0, -1, 1, 0, 1, 0, 1, 0, -1, -1, -1, 0,
		-1, 1, 1, 0, 0, 0, -1, 0, 1, 0, 0, -1, -1, 0, 0,
		1, 0, 1, -1, 1, -1, 1, 1, 1, 0, 0, 1, 1, -1, -1,
		0, 1, 0, 0, 0, 0, -1,
	}
	exp := []byte{
		0xaf, 0x4e, 0x54, 0xb4, 0x5b, 0x4e, 0x0e, 0x21,
		0x18, 0x91, 0x29, 0xe4, 0x03, 0x06,
	}
	p := polynomial.NewFromCoeffs(input)
	out := bytes.NewBuffer(nil)

	if err := EncodeTrinomial(p, out); err != nil {
		t.Error(err)
	}
	if bytes.Compare(out.Bytes(), exp) != 0 {
		t.Error("out != exp")
	}
}

func TestInvertibility(t *testing.T) {
	for _, v := range testvectors.TestVectors {
		p := polynomial.NewFromCoeffs(v.F)
		out := bytes.NewBuffer(nil)
		if err := EncodeTrinomial(p, out); err != nil {
			t.Error(err)
		}
		in := bytes.NewBuffer(out.Bytes())
		p2, err := GenTrinomial(len(v.F), in)
		if err != nil {
			t.Error(err)
		}
		if !p.Equals(p2) {
			t.Error("p != p2")
		}
	}
}
