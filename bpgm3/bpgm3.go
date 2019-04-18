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

// Package bpgm3 implements the BPGM3 algorithm defined in the X9.98 spec.
package bpgm3

import (
	"github.com/Wondertan/ntru/igf2"
	"github.com/Wondertan/ntru/polynomial"
)

// GenTrinomial generates a trinonial of degree N-1 that has numOnes
// coefficients set to +1 and numNegones coefficients set to -1, and all other
// coefficients set to 0.
func GenTrinomial(n, numOnes, numNegOnes int16, igf *igf2.IGF2) (*polynomial.Full, error) {
	isSet := make([]bool, n)
	p := polynomial.New(int(n))
	for t := int16(0); t < numOnes; {
		i, err := igf.NextIndex()
		if err != nil {
			return nil, err
		}
		if isSet[i] {
			continue
		}
		p.P[i] = 1
		isSet[i] = true
		t++
	}
	for t := int16(0); t < numNegOnes; {
		i, err := igf.NextIndex()
		if err != nil {
			return nil, err
		}
		if isSet[i] {
			continue
		}
		p.P[i] = -1
		isSet[i] = true
		t++
	}
	return p, nil
}
