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

// Package testvectors contains the NTRUEncrypt test vectors used for the unit
// tests.
package testvectors

import (
	"github.com/yawning/ntru/params"
)

// TestVector contains test vector data for a single OID.
type TestVector struct {
	OID        params.Oid
	OIDBytes   []byte
	KeygenSeed []byte
	F          []int16
	Ff         []int16 // f
	G          []int16
	H          []int16

	M           []byte
	EncryptSeed []byte
	B           []byte
	Mbin        []byte  // = b||l||m||p0 =
	Mtrin       []int16 //  = trinary b||l||m||p0 =
	SData       []byte  // o||m||b||h =
	Rr          []int16 // r
	R           []int16 // r * h
	R4          []byte  // r * h mod 4
	Mask        []int16
	MPrime      []int16 // m'
	E           []int16
	PackedE     []byte

	A  []int16 // = e * f
	Aa []int16 // = e * f reduced to [-q/2..q/2]

	PackedH       []byte
	PackedF       []byte
	PackedListedF []byte
}

// TestVectors is a map of test vectors for all of the OIDs that are supported.
var TestVectors map[params.Oid]*TestVector

func init() {
	TestVectors = make(map[params.Oid]*TestVector)

	TestVectors[ees401ep1.OID] = ees401ep1
	TestVectors[ees449ep1.OID] = ees449ep1
	TestVectors[ees677ep1.OID] = ees677ep1
	TestVectors[ees1087ep2.OID] = ees1087ep2
	TestVectors[ees541ep1.OID] = ees541ep1
	TestVectors[ees613ep1.OID] = ees613ep1
	TestVectors[ees887ep1.OID] = ees887ep1
	TestVectors[ees1171ep1.OID] = ees1171ep1
	TestVectors[ees659ep1.OID] = ees659ep1
	TestVectors[ees761ep1.OID] = ees761ep1
	TestVectors[ees1087ep1.OID] = ees1087ep1
	TestVectors[ees1499ep1.OID] = ees1499ep1
}

func ArrayEquals(a, b []int16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
