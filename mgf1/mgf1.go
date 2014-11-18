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

// Package mgf1 implements a io.Reader/ByteReader based on the MGF-1 algorithm
// defined in the PKCS#1 spec.
package mgf1

import (
	"encoding/binary"
	"hash"
	"io"
)

// MGF1 implements a reader based on the MGF-1 algorithm defined in the PKCS#1
// spec.
type MGF1 struct {
	seedAndCounter []byte
	digest         hash.Hash
	outputStream   []byte
	outputUsed     int
	minNumRuns     int
	numRuns        int
}

func (m *MGF1) ReadByte() (c byte, err error) {
	if m.outputUsed >= len(m.outputStream) {
		m.fillBuffer()
	}
	c = m.outputStream[m.outputUsed]
	m.outputUsed++
	return
}

func (m *MGF1) Read(p []byte) (n int, err error) {
	offset := 0
	toRead := len(p)
	for toRead > 0 {
		if m.outputUsed >= len(m.outputStream) {
			m.fillBuffer()
		}

		nn := len(m.outputStream) - m.outputUsed
		if nn > toRead {
			nn = toRead
		}
		copy(p[offset:], m.outputStream[m.outputUsed:m.outputUsed+nn])
		m.outputUsed += nn
		offset += nn
		toRead -= nn
	}
	return len(p), nil
}

func (m *MGF1) Close() error {
	for m.numRuns < m.minNumRuns {
		m.fillBuffer()
	}
	return nil
}

func (m *MGF1) fillBuffer() {
	seedOffset := len(m.seedAndCounter) - 4
	m.numRuns++
	m.outputUsed = 0
	m.digest.Write(m.seedAndCounter)
	m.outputStream = m.digest.Sum(m.outputStream[0:0])
	m.digest.Reset()

	x := binary.BigEndian.Uint32(m.seedAndCounter[seedOffset:])
	binary.BigEndian.PutUint32(m.seedAndCounter[seedOffset:], x+1)
}

// New creates a MGF1.
func New(hashFn func() hash.Hash, minNumRuns int, hashSeed bool, seed []byte, seedOffset, seedLength int) (m *MGF1) {
	// TODO: Change this to be more Go like, using slices and shit.
	// As far as I can tell nothing actually specifies a different seedOffset?
	m = &MGF1{digest: hashFn(), minNumRuns: minNumRuns}
	if hashSeed {
		ctr := [4]byte{}
		m.seedAndCounter = make([]byte, 0, m.digest.Size()+4)
		m.digest.Write(seed[seedOffset : seedOffset+seedLength])
		m.seedAndCounter = m.digest.Sum(m.seedAndCounter)
		seedLength = m.digest.Size()
		m.digest.Reset()
		m.seedAndCounter = append(m.seedAndCounter, ctr[:]...)
	} else {
		// Only used for testing...
		m.seedAndCounter = make([]byte, seedLength+4)
		copy(m.seedAndCounter[:], seed[seedOffset:seedOffset+seedLength])
	}
	m.outputStream = make([]byte, m.digest.Size())
	m.outputUsed = len(m.outputStream)
	return
}

var _ io.ByteReader = (*MGF1)(nil)
var _ io.Reader = (*MGF1)(nil)
var _ io.Closer = (*MGF1)(nil)
