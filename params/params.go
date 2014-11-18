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

// Package params stores the various NTRUEncrypt parameters.
package params

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
)

const (
	//
	// Best bandwidth (X9.98 compatible)
	//

	// EES401EP1 is the parameter set identifier for "ees401ep1".
	//  Security level:          112 bits
	//  Max plaintext length:    60 bytes
	//  Ciphertext length:       552 bytes
	//  Public Key blob length:  556 bytes
	//  Private Key blob length: 639 bytes
	EES401EP1 Oid = iota

	// EES449EP1 is the parameter set identifier for "ees449ep1"
	//  Security level:          128 bits
	//  Max plaintext length:    67 bytes
	//  Ciphertext length:       618 bytes
	//  Public Key blob length:  622 bytes
	//  Private Key blob length: 712 bytes
	EES449EP1

	// EES677EP1 is the parameter set identifier for "ees677ep1"
	//  Security level:          192 bits
	//  Max plaintext length:    101 bytes
	//  Ciphertext length:       931 bytes
	//  Public Key blob length:  935 bytes
	//  Private Key blob length: 1071 bytes
	EES677EP1

	// EES1087EP2 is the parameter set identifier for "ees1087ep2"
	//  Security level:          256 bits
	//  Max plaintext length:    170 bytes
	//  Ciphertext length:       1495 bytes
	//  Public Key blob length:  1499 bytes
	//  Private Key blob length: 1717 bytes
	EES1087EP2

	//
	// Balace of speed and bandwidth (X9.98 compatible)
	//

	// EES541EP1 is the parameter set identifier for "ees541ep1".
	//  Security level:          112 bits
	//  Max plaintext length:    86 bytes
	//  Ciphertext length:       744 bytes
	//  Public Key blob length:  748 bytes
	//  Private Key blob length: 857 bytes
	EES541EP1

	// EES613EP1 is the parameter set identifier for "ees613ep1".
	//  Security level:          128 bits
	//  Max plaintext length:    97 bytes
	//  Ciphertext length:       843 bytes
	//  Public Key blob length:  847 bytes
	//  Private Key blob length: 970 bytes
	EES613EP1

	// EES887EP1 is the parameter set identifier for "ees887ep1".
	//  Security level:          192 bits
	//  Max plaintext length:    141 bytes
	//  Ciphertext length:       1220 bytes
	//  Public Key blob length:  1224 bytes
	//  Private Key blob length: 1402 bytes
	EES887EP1

	// EES1171EP1 is the parameter set identifier for "ees1171ep1".
	//  Security level:          256 bits
	//  Max plaintext length:    186 bytes
	//  Ciphertext length:       1611 bytes
	//  Public Key blob length:  1615 bytes
	//  Private Key blob length: 1850 bytes
	EES1171EP1

	//
	// Best speed (X9.98 compatible)
	//

	// EES659EP1 is the parameter set identifier for "ees659ep1".
	//  Security level:          112 bits
	//  Max plaintext length:    108 bytes
	//  Ciphertext length:       907 bytes
	//  Public Key blob length:  911 bytes
	//  Private Key blob length: 1006 bytes
	EES659EP1

	// EES761EP1 is the parameter set identifier for "ees761ep1".
	//  Security level:          128 bits
	//  Max plaintext length:    125 bytes
	//  Ciphertext length:       1047 bytes
	//  Public Key blob length:  1051 bytes
	//  Private Key blob length: 1156 bytes
	EES761EP1

	// EES1087EP1 is the parameter set identifier for "ees1087ep1".
	//  Security level:          192 bits
	//  Max plaintext length:    178 bytes
	//  Ciphertext length:       1495 bytes
	//  Public Key blob length:  1499 bytes
	//  Private Key blob length: 1673 bytes
	EES1087EP1

	// EES1499EP1 is the parameter set identifier for "ees1499ep1".
	//  Security level:          256 bits
	//  Max plaintext length:    247 bytes
	//  Ciphertext length:       2062 bytes
	//  Public Key blob length:  2066 bytes
	//  Private Key blob length: 2284 bytes
	EES1499EP1

	// Note: EES401EP2, EES439EP1, EES593EP1 and EES743EP1 are extra-encumbered
	// according to the libntru source (2020 patent expiration vs 2017), and
	// not present in the Java reference code anyway so are not supported.
)

// Oid is a NTRUEncrypt parameter set identifier.
type Oid int

// KeyParams contains encryption parameters for a single parameter set.
type KeyParams struct {
	OID            Oid
	OIDBytes       []byte
	N              int16
	P              int16
	Q              int16
	Df             int16
	Dg             int16
	LLen           int16
	Db             int16
	MaxMsgLenBytes int
	BufferLenBits  int
	BufferLenTrits int
	Dm0            int16

	// Mask generation params, used in the generation of mask from R mod 4.
	MGFHash func() hash.Hash

	// BPGM3 params
	IGFHash      func() hash.Hash
	Dr           int16
	C            int16
	MinCallsR    int16
	MinCallsMask int16

	PkLen int
}

// Param returns the NTRUEncrypt parameters for a given parameter set.  The
// datastructure returned from this should be treated as read-only.
func Param(oid Oid) *KeyParams {
	return keyParamMap[oid]
}

// ParamFromBytes returns the NTRUEncrypt parameters for a given binary OID.
// The datastructure returned from this should be treated as read-only.
func ParamFromBytes(oid []byte) *KeyParams {
	for _, p := range keyParamMap {
		if bytes.Compare(oid, p.OIDBytes) == 0 {
			return p
		}
	}
	return nil
}

var keyParamMap map[Oid]*KeyParams

func init() {
	keyParamMap = make(map[Oid]*KeyParams)

	// Best bandwidth (X9.98 compatible)
	keyParamMap[EES401EP1] = &KeyParams{
		OID:            EES401EP1,
		OIDBytes:       []byte{0, 2, 4},
		N:              401,
		P:              3,
		Q:              2048,
		Df:             113,
		Dg:             133,
		LLen:           1,
		Db:             112,
		MaxMsgLenBytes: 60,
		BufferLenBits:  600,
		BufferLenTrits: 400,
		Dm0:            113,
		MGFHash:        sha1.New,
		IGFHash:        sha1.New,
		Dr:             113,
		C:              11,
		MinCallsR:      32,
		MinCallsMask:   9,
		PkLen:          112,
	}
	keyParamMap[EES449EP1] = &KeyParams{
		OID:            EES449EP1,
		OIDBytes:       []byte{0, 3, 3},
		N:              449,
		P:              3,
		Q:              2048,
		Df:             134,
		Dg:             149,
		LLen:           1,
		Db:             128,
		MaxMsgLenBytes: 67,
		BufferLenBits:  672,
		BufferLenTrits: 448,
		Dm0:            134,
		MGFHash:        sha1.New,
		IGFHash:        sha1.New,
		Dr:             134,
		C:              9,
		MinCallsR:      31,
		MinCallsMask:   9,
		PkLen:          128,
	}
	keyParamMap[EES677EP1] = &KeyParams{
		OID:            EES677EP1,
		OIDBytes:       []byte{0, 5, 3},
		N:              677,
		P:              3,
		Q:              2048,
		Df:             157,
		Dg:             225,
		LLen:           1,
		Db:             192,
		MaxMsgLenBytes: 101,
		BufferLenBits:  1008,
		BufferLenTrits: 676,
		Dm0:            157,
		MGFHash:        sha256.New,
		IGFHash:        sha256.New,
		Dr:             157,
		C:              11,
		MinCallsR:      27,
		MinCallsMask:   9,
		PkLen:          192,
	}
	keyParamMap[EES1087EP2] = &KeyParams{
		OID:            EES1087EP2,
		OIDBytes:       []byte{0, 6, 3},
		N:              1087,
		P:              3,
		Q:              2048,
		Df:             120,
		Dg:             362,
		LLen:           1,
		Db:             256,
		MaxMsgLenBytes: 170,
		BufferLenBits:  1624,
		BufferLenTrits: 1086,
		Dm0:            120,
		MGFHash:        sha256.New,
		IGFHash:        sha256.New,
		Dr:             120,
		C:              13,
		MinCallsR:      25,
		MinCallsMask:   14,
		PkLen:          256,
	}

	// Balace of speed and bandwidth (X9.98 compatible)
	keyParamMap[EES541EP1] = &KeyParams{
		OID:            EES541EP1,
		OIDBytes:       []byte{0, 2, 5},
		N:              541,
		P:              3,
		Q:              2048,
		Df:             49,
		Dg:             180,
		LLen:           1,
		Db:             112,
		MaxMsgLenBytes: 86,
		BufferLenBits:  808,
		BufferLenTrits: 540,
		Dm0:            49,
		MGFHash:        sha1.New,
		IGFHash:        sha1.New,
		Dr:             49,
		C:              12,
		MinCallsR:      15,
		MinCallsMask:   11,
		PkLen:          112,
	}
	keyParamMap[EES613EP1] = &KeyParams{
		OID:            EES613EP1,
		OIDBytes:       []byte{0, 3, 4},
		N:              613,
		P:              3,
		Q:              2048,
		Df:             55,
		Dg:             204,
		LLen:           1,
		Db:             128,
		MaxMsgLenBytes: 97,
		BufferLenBits:  912,
		BufferLenTrits: 612,
		Dm0:            55,
		MGFHash:        sha1.New,
		IGFHash:        sha1.New,
		Dr:             55,
		C:              11,
		MinCallsR:      16,
		MinCallsMask:   13,
		PkLen:          128,
	}
	keyParamMap[EES887EP1] = &KeyParams{
		OID:            EES887EP1,
		OIDBytes:       []byte{0, 5, 4},
		N:              887,
		P:              3,
		Q:              2048,
		Df:             81,
		Dg:             295,
		LLen:           1,
		Db:             192,
		MaxMsgLenBytes: 141,
		BufferLenBits:  1328,
		BufferLenTrits: 886,
		Dm0:            81,
		MGFHash:        sha256.New,
		IGFHash:        sha256.New,
		Dr:             81,
		C:              10,
		MinCallsR:      13,
		MinCallsMask:   12,
		PkLen:          192,
	}
	keyParamMap[EES1171EP1] = &KeyParams{
		OID:            EES1171EP1,
		OIDBytes:       []byte{0, 6, 4},
		N:              1171,
		P:              3,
		Q:              2048,
		Df:             106,
		Dg:             390,
		LLen:           1,
		Db:             256,
		MaxMsgLenBytes: 186,
		BufferLenBits:  1752,
		BufferLenTrits: 1170,
		Dm0:            106,
		MGFHash:        sha256.New,
		IGFHash:        sha256.New,
		Dr:             106,
		C:              12,
		MinCallsR:      20,
		MinCallsMask:   15,
		PkLen:          256,
	}

	// Best speed (X9.98 compatible)
	keyParamMap[EES659EP1] = &KeyParams{
		OID:            EES659EP1,
		OIDBytes:       []byte{0, 2, 6},
		N:              659,
		P:              3,
		Q:              2048,
		Df:             38,
		Dg:             219,
		LLen:           1,
		Db:             112,
		MaxMsgLenBytes: 108,
		BufferLenBits:  984,
		BufferLenTrits: 658,
		Dm0:            38,
		MGFHash:        sha1.New,
		IGFHash:        sha1.New,
		Dr:             38,
		C:              11,
		MinCallsR:      11,
		MinCallsMask:   14,
		PkLen:          112,
	}
	keyParamMap[EES761EP1] = &KeyParams{
		OID:            EES761EP1,
		OIDBytes:       []byte{0, 3, 5},
		N:              761,
		P:              3,
		Q:              2048,
		Df:             42,
		Dg:             253,
		LLen:           1,
		Db:             128,
		MaxMsgLenBytes: 125,
		BufferLenBits:  1136,
		BufferLenTrits: 760,
		Dm0:            42,
		MGFHash:        sha1.New,
		IGFHash:        sha1.New,
		Dr:             42,
		C:              12,
		MinCallsR:      13,
		MinCallsMask:   16,
		PkLen:          128,
	}
	keyParamMap[EES1087EP1] = &KeyParams{
		OID:            EES1087EP1,
		OIDBytes:       []byte{0, 5, 5},
		N:              1087,
		P:              3,
		Q:              2048,
		Df:             63,
		Dg:             362,
		LLen:           1,
		Db:             192,
		MaxMsgLenBytes: 178,
		BufferLenBits:  1624,
		BufferLenTrits: 1086,
		Dm0:            63,
		MGFHash:        sha256.New,
		IGFHash:        sha256.New,
		Dr:             63,
		C:              13,
		MinCallsR:      13,
		MinCallsMask:   14,
		PkLen:          192,
	}
	keyParamMap[EES1499EP1] = &KeyParams{
		OID:            EES1499EP1,
		OIDBytes:       []byte{0, 6, 5},
		N:              1499,
		P:              3,
		Q:              2048,
		Df:             79,
		Dg:             499,
		LLen:           1,
		Db:             256,
		MaxMsgLenBytes: 247,
		BufferLenBits:  2240,
		BufferLenTrits: 1498,
		Dm0:            79,
		MGFHash:        sha256.New,
		IGFHash:        sha256.New,
		Dr:             79,
		C:              13,
		MinCallsR:      17,
		MinCallsMask:   19,
		PkLen:          256,
	}
}
