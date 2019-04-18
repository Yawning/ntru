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

// Package igf2 implements the IGF2 Index Generation Function defined in the
// X9.92 spec for NTRUEncrypt.
package igf2

import (
	"hash"
	"io"

	"github.com/Wondertan/ntru/mgf1"
)

// IGF2 implements the IGF2 Index Generation Function defined in the X9.92 spec
// for NTRUEncrypt.
type IGF2 struct {
	maxValue        int16
	bitsPerIndex    int16
	leftoverBits    int
	numLeftoverBits int
	cutoff          int
	source          io.ByteReader
}

// NextIndex derives the next index.
func (g *IGF2) NextIndex() (int16, error) {
	ret := 0
	for {
		// Make sure leftoverBits has at least bitsPerIndex in it.
		for g.numLeftoverBits < int(g.bitsPerIndex) {
			g.leftoverBits <<= 8
			c, err := g.source.ReadByte()
			if err != nil {
				return 0, err
			}
			g.leftoverBits |= int(c)
			g.numLeftoverBits += 8
		}

		// Pull off bitsPerIndex from leftoverBits.  Store in ret.
		shift := g.numLeftoverBits - int(g.bitsPerIndex)
		ret = 0xffff & (g.leftoverBits >> uint(shift))
		g.numLeftoverBits = shift
		g.leftoverBits &= ((1 << uint(g.numLeftoverBits)) - 1)

		if ret < g.cutoff {
			return int16(ret) % g.maxValue, nil
		}
	}
}

func (g *IGF2) Close() error {
	if closer, ok := (g.source).(io.Closer); ok {
		return closer.Close()
	}
	return nil // Oh well...
}

// New creates an IGF2 driven by a MGF1.
func New(maxValue, bitsPerIndex int16, hashFn func() hash.Hash, minNumRuns int, seed []byte, seedOff, seedLen int) *IGF2 {
	mgf := mgf1.New(hashFn, minNumRuns, true, seed, seedOff, seedLen)
	return NewFromReader(maxValue, bitsPerIndex, mgf)
}

// NewFromReader creates an IGF2 driven by a io.ByteReader.
func NewFromReader(maxValue, bitsPerIndex int16, source io.ByteReader) *IGF2 {
	g := &IGF2{}
	g.maxValue = int16(maxValue)
	g.bitsPerIndex = int16(bitsPerIndex)
	g.source = source
	modulus := 1 << uint(bitsPerIndex)
	g.cutoff = modulus - (modulus % int(maxValue))
	return g
}
