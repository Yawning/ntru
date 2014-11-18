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

package igf2

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/yawning/ntru/testvectors"
)

func checkIGF(bitsPerElement int16, input []byte, expected []int16) error {
	source := bytes.NewBuffer(input)
	out := make([]int16, len(expected))
	igf := NewFromReader(1<<uint(bitsPerElement), bitsPerElement, source)
	for i := range out {
		tmp, err := igf.NextIndex()
		if err != nil {
			return err
		}
		out[i] = int16(tmp)
	}
	if ok := testvectors.ArrayEquals(expected, out); !ok {
		return fmt.Errorf("src != exp")
	}
	return nil
}

func TestIGF2(t *testing.T) {
	vectors := []struct {
		src   []byte
		exp   []int16
		nBits int16
	}{
		// test_8bit
		{
			[]byte{
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88,
			},
			[]int16{
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88,
			},
			8,
		},
		// test_9bit
		{
			[]byte{
				0x40, 0x20, 0x50, 0x48, 0x34, 0x22, 0x15, 0x0c,
				0x87, 0x44, 0x00,
			},
			[]int16{
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88,
			},
			9,
		},
		// test_10bit
		{
			[]byte{
				0x20, 0x08, 0x12, 0x08, 0x83, 0x21, 0x08, 0x52,
				0x18, 0x87, 0x22, 0x00,
			},
			[]int16{
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88,
			},
			10,
		},
		// test_11bit
		{
			[]byte{
				0x10, 0x02, 0x04, 0x41, 0x08, 0x31, 0x08, 0x21,
				0x44, 0x30, 0x87, 0x11, 0x00,
			},
			[]int16{
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88,
			},
			11,
		},
		// test_12bit
		{
			[]byte{
				0x08, 0x00, 0x81, 0x08, 0x20, 0x83, 0x08, 0x40,
				0x85, 0x08, 0x60, 0x87, 0x08, 0x80,
			},
			[]int16{
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88,
			},
			12,
		},
	}

	for _, v := range vectors {
		if err := checkIGF(v.nBits, v.src, v.exp); err != nil {
			t.Errorf("[%d]: %v", v.nBits, err)
		}
	}
}
