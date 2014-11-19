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

// Package polynomial provides an abstraction of a polynomial.
package polynomial

// Full is a polynomial represented by a slice of 16 bit signed coefficients.
type Full struct {
	// P is the list of coefficients of the polynomial.
	P []int16
}

// getDegree returns the degree of a polynomial.
func (a *Full) getDegree() (df int) {
	df = len(a.P) - 1
	for df > 0 && a.P[df] == 0 {
		df--
	}
	return
}

// divideByX divides f(X) by the polynomial g(X) = X.
func (a *Full) divideByX() {
	f0 := a.P[0]
	for i := 0; i < len(a.P)-1; i++ {
		a.P[i] = a.P[i+1]
	}
	a.P[len(a.P)-1] = f0
}

// multiplyByX multiplys the f(X) by the polynomial g(X) = X.
func (a *Full) multiplyByX() {
	f0 := a.P[len(a.P)-1]
	for i := len(a.P) - 1; i > 0; i-- {
		a.P[i] = a.P[i-1]
	}
	a.P[0] = f0
}

// recenterModQ recenters the coefficients of a polynomial into the range
// [newLowerLimit..newLowerLimit+q), such that the new coefficients equal the
// old coefficients mod q.
func (a *Full) recenterModQ(q, newLowerLimit int) {
	newUpperLimit := newLowerLimit + q
	for i := range a.P {
		tmp := int(a.P[i]) % q
		if tmp >= newUpperLimit {
			tmp -= q
		}
		if tmp < newLowerLimit {
			tmp += q
		}
		a.P[i] = int16(tmp)
	}
}

// Convolution computes a*b in the ring of polynomials of degree N, given two
// polynomials of the same degree N.
func Convolution(a, b *Full) (c *Full) {
	if len(a.P) != len(b.P) {
		// XXX: Does this happen ever?
		c = New(0)
	} else {
		c = New(len(a.P))
		for i := range a.P {
			for j := range b.P {
				c.P[(i+j)%len(c.P)] += (a.P[i] * b.P[j])
			}
		}
	}
	return
}

// ConvolutionModN computes a*b in the ring of polynomials of degree N whose
// coefficients are in the ring of integers mod coefficientModulus.
func ConvolutionModN(a, b *Full, coefficientModulus int) (c *Full) {
	c = Convolution(a, b)
	c.recenterModQ(coefficientModulus, 0)
	return
}

// Add adds two polynomials modulo coefficientModulus.  The coefficients of the
// resulting polynomial will be in the range [0..coefficientModulus-1].
func (a *Full) Add(b *Full, coefficientModulus int) (c *Full) {
	return a.AddAndRecenter(b, coefficientModulus, 0)
}

// AddAndRecenter adds two polynomials modulo coefficientModulus and recenters
// the coefficients of the resulting polynomial to the range
// [newLowerLimit..newLowerLimit+coefficientModulus-1].
func (a *Full) AddAndRecenter(b *Full, coefficientModulus, newLowerLimit int) (c *Full) {
	c = New(len(a.P))
	for i := range c.P {
		c.P[i] = a.P[i] + b.P[i]
	}
	c.recenterModQ(coefficientModulus, newLowerLimit)
	return
}

// Subtract subtracts two polynomials modulo coefficientModulus.  The
// coefficients of the resulting polynomial will be in the range
// [0..coefficientModulus-1].
func (a *Full) Subtract(b *Full, coefficientModulus int) (c *Full) {
	return a.SubtractAndRecenter(b, coefficientModulus, 0)
}

// SubtractAndRecenter subtracts two polynomials modulo coefficientModulus and
// recenters the coefficients of the resulting polynomial to the range
// [newLowerLimit..newLowerLimit+coefficientModulus-1].
func (a *Full) SubtractAndRecenter(b *Full, coefficientModulus, newLowerLimit int) (c *Full) {
	c = New(len(a.P))
	for i := range c.P {
		c.P[i] = a.P[i] - b.P[i]
	}
	c.recenterModQ(coefficientModulus, newLowerLimit)
	return
}

// Equals compares two polynomials.
func (a *Full) Equals(b *Full) bool {
	if len(a.P) != len(b.P) {
		return false
	}
	res := int16(0)
	for i := range a.P {
		res |= a.P[i] ^ b.P[i]
	}
	return res == 0
}

// Obliterate clears the contents of the polynomial.
func (a *Full) Obliterate() {
	for i := range a.P {
		a.P[i] = 0
	}
}

// NewFromCoeffs initializes a polynomial with the given coefficient list.
func NewFromCoeffs(coeffs []int16) (p *Full) {
	p = New(len(coeffs))
	copy(p.P, coeffs)
	return
}

// New initializes a polynomial of degree n whose coefficients are all 0.
func New(n int) (p *Full) {
	p = &Full{}
	p.P = make([]int16, n)
	return
}
