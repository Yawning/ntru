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

package bitpack

import (
	"bytes"
	"testing"

	"github.com/yawning/ntru/testvectors"
)

func TestLowBitMask(t *testing.T) {
	expectedMasks := []int32{
		0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
		0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff,
	}
	for i, eMask := range expectedMasks {
		m := lowBitMask(uint(i) + 1)
		if m != eMask {
			t.Errorf("lowBitMask(%d) != %x (got: %x)", i, eMask, m)
		}
	}
}

func TestPackedLength(t *testing.T) {
	vec := []struct {
		expected, numElts, maxEltValue int
	}{
		{12, 12, 0x100},
		{(12*9 + 7) / 8, 12, 0x200},
		{(14*10 + 7) / 8, 14, 0x400},
		{(21*11 + 7) / 8, 21, 0x800},
		{(13*12 + 7) / 8, 13, 0x1000},
		{(19*13 + 7) / 8, 19, 0x2000},
		{(19*14 + 7) / 8, 19, 0x4000},
		{(19*15 + 7) / 8, 19, 0x8000},
		{(19*16 + 7) / 8, 19, 0x10000},
	}
	for _, v := range vec {
		l := PackedLength(v.numElts, v.maxEltValue)
		if l != v.expected {
			t.Errorf("PackedLength(%d, %x) != %d (got: %d)", v.numElts, v.maxEltValue, v.expected, l)
		}
	}
}

func TestPack(t *testing.T) {
	vec := []struct {
		expected []byte
		src      []int16
		maxVal   int
	}{
		// test_pack5
		{
			[]byte{0x80, 0x63, 0xf0, 0x4b, 0x5c, 0x08},
			[]int16{0x10, 0x01, 0x11, 0x1f, 0x00, 0x12, 0x1a, 0x1c, 0x01},
			0x20,
		},
		// test_pack8
		{
			[]byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x100,
		},
		// test_pack9
		{
			[]byte{0x40, 0x20, 0x50, 0x48, 0x34, 0x22, 0x15, 0x0c, 0x87, 0x44, 0x00},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x200,
		},
		// test_pack10
		{
			[]byte{0x20, 0x08, 0x12, 0x08, 0x83, 0x21, 0x08, 0x52, 0x18, 0x87, 0x22, 0x00},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x400,
		},
		// test_pack11
		{
			[]byte{0x10, 0x02, 0x04, 0x41, 0x08, 0x31, 0x08, 0x21, 0x44, 0x30, 0x87, 0x11, 0x00},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x800,
		},
		// test_pack12
		{
			[]byte{0x08, 0x00, 0x81, 0x08, 0x20, 0x83, 0x08, 0x40, 0x85, 0x08, 0x60, 0x87, 0x08, 0x80},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x1000,
		},
	}
	for _, v := range vec {
		tgt := make([]byte, len(v.expected))
		l := Pack(len(v.src), v.maxVal, v.src, 0, tgt, 0)
		if l != len(v.expected) {
			t.Errorf("Pack(%d, %x, %v, 0, tgt, 0) != %d (got: %d)", len(v.src), v.maxVal, v.src, len(v.expected), l)
		}
		if bytes.Compare(v.expected, tgt) != 0 {
			t.Errorf("Pack(%d, %x, %v, 0, tgt, 0): tgt != expected", len(v.src), v.maxVal, v.src)
		}
	}
}

func TestPackN(t *testing.T) {
	vec := []struct {
		expected []byte
		src      []int16
		maxVal   int
		maxLen   int
	}{
		// test_pack9_limited
		{
			[]byte{0x40, 0x20, 0x50},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x200,
			3,
		},
		// test_pack12_limited
		{
			[]byte{0x08, 0x00, 0x81, 0x08, 0x20, 0x83},
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x1000,
			6,
		},
	}
	for _, v := range vec {
		tgt := make([]byte, len(v.expected))
		l := PackN(len(v.src), v.maxVal, v.maxLen, v.src, 0, tgt, 0)
		if l != len(v.expected) {
			t.Errorf("PackN(%d, %x, %d, %v, 0, tgt, 0) != %d (got: %d)", len(v.src), v.maxVal, v.maxLen, v.src, len(v.expected), l)
		}
		if bytes.Compare(v.expected, tgt) != 0 {
			t.Errorf("Pack(%d, %x, %d, %v, 0, tgt, 0): tgt != expected", len(v.src), v.maxVal, v.maxLen, v.src)
		}
	}

	// test_pack12_long
	src := []int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88}
	expected := []byte{0x08, 0x00, 0x81, 0x08, 0x20, 0x83, 0x08, 0x40, 0x85, 0x08, 0x60, 0x87, 0x08, 0x80}
	tgt := make([]byte, len(expected)+10)
	l := PackN(len(src), 0x1000, len(tgt), src, 0, tgt, 0)
	if l != len(expected) {
		t.Errorf("PackN(%d, %x, %d, %v, 0, tgt, 0) != %d (got: %d)", len(src), 0x1000, len(tgt), src, len(expected), l)
	}
	if bytes.Compare(expected, tgt[0:len(expected)]) != 0 {
		t.Errorf("PackN(%d, %x, %d, %v, 0, tgt, 0): tgt != expected", len(src), 0x1000, len(tgt), src)
	}
}

func TestUnpack(t *testing.T) {
	vec := []struct {
		expected []int16
		src      []byte
		maxVal   int
	}{
		// test_unpack5
		{
			[]int16{0x10, 0x01, 0x11, 0x1f, 0x00, 0x12, 0x1a, 0x1c, 0x01},
			[]byte{0x80, 0x63, 0xf0, 0x4b, 0x5c, 0x08},
			0x20,
		},
		// test_unpack8
		{
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			[]byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			0x100,
		},
		// test_unpack9
		{
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			[]byte{0x40, 0x20, 0x50, 0x48, 0x34, 0x22, 0x15, 0x0c, 0x87, 0x44, 0x00},

			0x200,
		},
		// test_unpack10
		{
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			[]byte{0x20, 0x08, 0x12, 0x08, 0x83, 0x21, 0x08, 0x52, 0x18, 0x87, 0x22, 0x00},
			0x400,
		},
		// test_unpack11
		{
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			[]byte{0x10, 0x02, 0x04, 0x41, 0x08, 0x31, 0x08, 0x21, 0x44, 0x30, 0x87, 0x11, 0x00},
			0x800,
		},
		// test_unpack12
		{
			[]int16{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88},
			[]byte{0x08, 0x00, 0x81, 0x08, 0x20, 0x83, 0x08, 0x40, 0x85, 0x08, 0x60, 0x87, 0x08, 0x80},
			0x1000,
		},
	}
	for _, v := range vec {
		tgt := make([]int16, len(v.expected))
		l := Unpack(len(v.expected), v.maxVal, v.src, 0, tgt, 0)
		if l != len(v.src) {
			t.Errorf("Unpack(%d, %x, %v, 0, tgt, 0) != %d (got: %d)", len(v.expected), v.maxVal, v.src, len(v.expected), l)
		}
		if !testvectors.ArrayEquals(tgt, v.expected) {
			t.Errorf("Unpack(%d, %x, %v, 0, tgt, 0): tgt != expected", len(v.expected), v.maxVal, v.src)
		}
	}
}
