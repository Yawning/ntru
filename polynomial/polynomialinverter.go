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

// Inverter defines an interface for finding the inverse of a polynomial.
type Inverter interface {
	// Invert calculates the inverse of a polynomial.
	Invert(a *Full) *Full
}

// InverterModPrime implements the algorithm for finding the inverse of a
// polynomial in the ring (Z/pZ)[X]/(X^N-1) for some prime p.
type InverterModPrime struct {
	// prime is the modulus.
	prime int

	// invModPrime is a table of inverses mod prime, setup so that
	// invModPrime[i] * i = 1 (mod prime) if the inverse of i exists, and
	// invModPrime[i] = 0 if thte inverse of i does not exist.
	invModPrime []int16
}

// modPrime returns x mod prime, always in the range [0..prime-1].
func (v *InverterModPrime) modPrime(x int16) int16 {
	ret := int(x) % v.prime
	if ret < 0 {
		ret += v.prime
	}
	return int16(ret)
}

// Invert computes the inverse of a polynomial in (Z/pZ)[X]/(X^N-1).
// See NTRU Cryptosystems Tech Report #014 "Almost Inverses and Fast NTRU Key
// Creation."
func (v *InverterModPrime) Invert(a *Full) *Full {
	N := len(a.P)

	// Initialization:
	// k = 0, B(X) = 1, C(X) = 0, f(X)=a(X), g(X)=X^N-1
	k := 0
	b := New(N + 1)
	c := New(N + 1)
	f := New(N + 1)
	g := New(N + 1)
	b.P[0] = 1
	for i := 0; i < N; i++ {
		f.P[i] = v.modPrime(a.P[i])
	}
	g.P[N] = 1
	g.P[0] = int16(v.prime - 1)

	// Find the degree of f(X).
	df := f.getDegree()

	// Find the degre of g(X).  This is a constant based on initialization.
	dg := N

	for {
		// while f[0] = 0 {f/=X, c*=X, k++}
		for f.P[0] == 0 && df > 0 {
			df--
			f.divideByX()
			c.multiplyByX()
			k++
		}

		if df == 0 {
			// Make sure there is a solution, return nil if a is not invertible.
			f0Inv := v.invModPrime[f.P[0]]
			if f0Inv == 0 {
				return nil
			}

			// b(X) = f[0]inv * b(X) mod p
			// return X^(N-k) * b
			shift := N - k
			shift %= N
			if shift < N {
				shift += N
			}
			ret := New(N)
			for i := range ret.P {
				ret.P[(i+shift)%N] = v.modPrime(f0Inv * b.P[i])
			}
			return ret
		}

		if df < dg {
			// swap(f,g), swap(b,c), swap(df, dg)
			f, g = g, f
			b, c = c, b
			df, dg = dg, df
		}

		// u = f[0] * g[0]inv mod p
		u := v.modPrime(f.P[0] * v.invModPrime[g.P[0]])

		// f(X) -= u*g(X) mod p
		for i := range f.P {
			f.P[i] = v.modPrime(f.P[i] - u*g.P[i])
		}

		// b(X) -= u*c(X) mod p
		for i := range b.P {
			b.P[i] = v.modPrime(b.P[i] - u*c.P[i])
		}
	}
}

// NewInverterModPrime constructs a new InverterModPrime with the given prime
// and table of inverses mod prime.
func NewInverterModPrime(prime int, invModPrime []int16) *InverterModPrime {
	return &InverterModPrime{prime: prime, invModPrime: invModPrime}
}

// InverterModPowerOfPrime implements the algorithm for finding the inverse of
// a polynomial in the ring (Z/p^rZ)[X]/(X^N-1) for some prime p and some
// exponent r.
type InverterModPowerOfPrime struct {
	primeInv *InverterModPrime

	powerOfPrime int16
}

// Invert computes the inverse of a polynomial in (Z/p^rZ)[X]/(X^N-1).
// See NTRU Cryptosystems Tech Report #014 "Almost Inverses and Fast NTRU Key
// Creation."
func (v *InverterModPowerOfPrime) Invert(a *Full) *Full {
	// b = a inverse mod prime.
	b := v.primeInv.Invert(a)
	if b == nil {
		return nil
	}

	for q := int(v.primeInv.prime); q < int(v.powerOfPrime); {
		q *= q

		// b(X) = b(X) * (2-a(X)b(X)) (mod q)
		//  i : c = a*b
		c := ConvolutionModN(a, b, q)
		// ii : c = 2-a*b
		c.P[0] = 2 - c.P[0]
		if c.P[0] < 0 {
			c.P[0] += int16(q)
		}
		for i := 1; i < len(b.P); i++ {
			c.P[i] = int16(q - int(c.P[i])) // This is -c (mod q)
		}
		b = ConvolutionModN(b, c, q)
	}
	return b
}

// NewInverterModPowerOfPrime constructs a new InverterModPowerOfPrime with the
// given exponent, prime and table of inverses mod prime.
func NewInverterModPowerOfPrime(powerOfPrime int16, prime int, invModPrime []int16) *InverterModPowerOfPrime {
	v := &InverterModPowerOfPrime{powerOfPrime: powerOfPrime}
	v.primeInv = NewInverterModPrime(prime, invModPrime)
	return v
}

var _ Inverter = (*InverterModPrime)(nil)
var _ Inverter = (*InverterModPowerOfPrime)(nil)
