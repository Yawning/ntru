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

package bpgm3

import (
	"bytes"
	"testing"

	"github.com/yawning/ntru/igf2"
	"github.com/yawning/ntru/params"
	"github.com/yawning/ntru/polynomial"
	"github.com/yawning/ntru/testvectors"
)

func TestOddEven(t *testing.T) {
	igfSequence := []byte{
		0, 0, 0, 2, 0, 4, 0, 6,
		0, 8, 0, 1, 0, 3, 0, 5,
		0, 7, 0, 9,
	}
	is := bytes.NewBuffer(igfSequence)
	igf := igf2.NewFromReader(0x7fff, 16, is)
	polyCoeffs := []int16{1, -1, 1, -1, 1, -1, 1, -1, 1, -1}
	exp := polynomial.NewFromCoeffs(polyCoeffs)
	out, err := GenTrinomial(10, 5, 5, igf)
	if err != nil {
		t.Error(err)
	}
	if !exp.Equals(out) {
		t.Errorf("exp != out")
	}
}

func TestCollisions(t *testing.T) {
	igfSequence := []byte{
		0, 0, 0, 2, 0, 4, 0, 6,
		0, 0, 0, 2, 0, 4, 0, 6,
		0, 8, 0, 0, 0, 2, 0, 4,
		0, 6, 0, 8, 0, 1, 0, 3,
		0, 5, 0, 7, 0, 9,
	}
	is := bytes.NewBuffer(igfSequence)
	igf := igf2.NewFromReader(0x7fff, 16, is)
	polyCoeffs := []int16{1, -1, 1, -1, 1, -1, 1, -1, 1, -1}
	exp := polynomial.NewFromCoeffs(polyCoeffs)
	out, err := GenTrinomial(10, 5, 5, igf)
	if err != nil {
		t.Error(err)
	}
	if !exp.Equals(out) {
		t.Errorf("exp != out")
	}
}

func TestGenR(t *testing.T) {
	for oid, v := range testvectors.TestVectors {
		p := params.Param(oid)
		exp := polynomial.NewFromCoeffs(v.Rr)
		igf := igf2.New(p.N, p.C, p.IGFHash, 1, v.SData, 0, len(v.SData))
		out, err := GenTrinomial(p.N, p.Dr, p.Dr, igf)
		if err != nil {
			t.Errorf("[%d]: %v", oid, err)
		}
		if !exp.Equals(out) {
			t.Errorf("[%d]: exp != out", oid)
		}
	}
}
