package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"
)

const (
	mpNull              = 0xc0
	mpFalse             = 0xc2
	mpTrue              = 0xc3
	mpBin8              = 0xc4
	mpBin16             = 0xc5
	mpBin32             = 0xc6
	mpExt8              = 0xc7
	mpExt16             = 0xc8
	mpExt32             = 0xc9
	mpFloat             = 0xca
	mpDouble            = 0xcb
	mpUint8             = 0xcc
	mpUint16            = 0xcd
	mpUint32            = 0xce
	mpUint64            = 0xcf
	mpInt8              = 0xd0
	mpInt16             = 0xd1
	mpInt32             = 0xd2
	mpInt64             = 0xd3
	mpFixExt1           = 0xd4
	mpFixExt2           = 0xd5
	mpFixExt4           = 0xd6
	mpFixExt8           = 0xd7
	mpFixExt16          = 0xd8
	mpStr8              = 0xd9
	mpStr16             = 0xda
	mpStr32             = 0xdb
	mpArray16           = 0xdc
	mpArray32           = 0xdd
	mpMap16             = 0xde
	mpMap32             = 0xdf
	mpFixStrMin         = 0xa0
	mpFixStrMax         = 0xbf
	mpFixArrayMin       = 0x90
	mpFixArrayMax       = 0x9f
	mpFixMapMin         = 0x80
	mpFixMapMax         = 0x8f
	mpFixArrayCountMask = 0xf
	mpFixMapCounMask    = 0xf
	mpFixstrCountMask   = 0x1f
	mpNegativeFixMin    = 0xe0
	mpNegativeFixMax    = 0xff
	mpNegativeFixMask   = 0x1f
	mpNegativeFixOffset = 0x20
	mpPositiveFixMax    = 0x7f
)

type StructStep struct {
	Index int
	Key   string
}

func newStructStepWithIndex(index int) StructStep {
	return StructStep{
		Index: index,
		Key:   "",
	}
}

func newStructStepWithKey(key string) StructStep {
	return StructStep{
		Index: -1,
		Key:   key,
	}
}

func (s StructStep) String() string {
	if s.Index >= 0 {
		return "[" + strconv.Itoa(s.Index) + "]"
	}
	return s.Key
}

func (s StructPath) String() string {
	if len(s) == 0 {
		return ""
	}
	parts := []string{""}
	for _, step := range s {
		parts = append(parts, step.String())
	}
	return strings.Join(parts, ".")
}

type StructPath []StructStep

const maxDepth = 64

type canonicalizer struct {
	buf  []byte
	path StructPath
}

func (c *canonicalizer) genErrStr(s string) error {
	return CanonicalEncodingError{
		Err:  errors.New(s),
		Path: c.path,
	}
}

func (c *canonicalizer) genErr(e error) error {
	return CanonicalEncodingError{
		Err:  e,
		Path: c.path,
	}
}

func (c *canonicalizer) readUint8() (uint8, error) {
	if len(c.buf) == 0 {
		return 0, c.genErrStr("buffer is empty")
	}
	b := c.buf[0]
	c.buf = c.buf[1:]
	return b, nil
}

func (c *canonicalizer) readUint16() (uint16, error) {
	if len(c.buf) < 2 {
		return 0, c.genErrStr("buffer is too short")
	}
	ret := binary.BigEndian.Uint16(c.buf[:2])
	c.buf = c.buf[2:]
	return ret, nil
}

func (c *canonicalizer) readUint32() (uint32, error) {
	if len(c.buf) < 4 {
		return 0, c.genErrStr("buffer is too short")
	}
	ret := binary.BigEndian.Uint32(c.buf[:4])
	c.buf = c.buf[4:]
	return ret, nil
}

func (c *canonicalizer) readInt8() (int8, error) {
	if len(c.buf) < 1 {
		return 0, c.genErrStr("buffer is empty")
	}
	b := c.buf[0]
	c.buf = c.buf[1:]
	return int8(b), nil
}

func (c *canonicalizer) readInt16() (int16, error) {
	if len(c.buf) < 2 {
		return 0, c.genErrStr("buffer is too short")
	}
	rdr := bytes.NewReader(c.buf[:2])
	var ret int16
	err := binary.Read(rdr, binary.BigEndian, &ret)
	if err != nil {
		return 0, err
	}
	c.buf = c.buf[2:]
	return ret, nil
}

func (c *canonicalizer) readInt32() (int32, error) {
	if len(c.buf) < 4 {
		return 0, c.genErrStr("buffer is too short")
	}
	rdr := bytes.NewReader(c.buf[:4])
	var ret int32
	err := binary.Read(rdr, binary.BigEndian, &ret)
	if err != nil {
		return 0, err
	}
	c.buf = c.buf[4:]
	return ret, nil
}

func (c *canonicalizer) readInt64() (int64, error) {
	if len(c.buf) < 8 {
		return 0, c.genErrStr("buffer is too short")
	}
	rdr := bytes.NewReader(c.buf[:8])
	var ret int64
	err := binary.Read(rdr, binary.BigEndian, &ret)
	if err != nil {
		return 0, err
	}
	c.buf = c.buf[8:]
	return ret, nil
}

func (c *canonicalizer) readUint64() (uint64, error) {
	if len(c.buf) < 8 {
		return 0, c.genErrStr("buffer is too short")
	}
	ret := binary.BigEndian.Uint64(c.buf[:8])
	c.buf = c.buf[8:]
	return ret, nil
}

func (c *canonicalizer) readString(n int) error {
	if len(c.buf) < n {
		return c.genErrStr("buffer is too short")
	}
	c.buf = c.buf[n:]
	return nil
}

func (c *canonicalizer) readShortString() (string, error) {
	u, err := c.readUint8()
	if err != nil {
		return "", err
	}
	if u < mpFixStrMin || u > mpFixStrMax {
		return "", c.genErrStr("invalid short string encoding for map key")
	}
	n := int(u & mpFixstrCountMask)
	if len(c.buf) < n {
		return "", c.genErrStr("buffer is too short")
	}
	s := string(c.buf[:n])
	c.buf = c.buf[n:]
	return s, nil
}

func (c *canonicalizer) runMap(n int) error {
	// Empty maps are allowed for unions without void data types.
	if n == 0 {
		return nil
	}
	if n != 1 {
		return c.genErrStr("map with more than one element not allowed")
	}
	len := len(c.path)

	s, err := c.readShortString()
	if err != nil {
		return err
	}
	c.path = append(c.path, newStructStepWithKey(s))
	err = c.run()
	if err != nil {
		return err
	}
	c.path = c.path[:len]
	return nil
}

func (c *canonicalizer) runArray(n int) error {
	if n == 0 {
		return c.genErrStr("empty array should be encoded as null")
	}

	len := len(c.path)
	for i := range n {
		c.path = append(c.path, newStructStepWithIndex(i))
		err := c.run()
		if err != nil {
			return err
		}
		c.path = c.path[:len]
	}
	return nil
}

func (c *canonicalizer) run() error {
	if len(c.path) > maxDepth {
		return c.genErrStr("max depth exceeded")
	}

	byt, err := c.readUint8()
	if err != nil {
		return c.genErr(err)
	}
	switch {
	case byt <= mpPositiveFixMax:
		return nil
	case byt >= mpFixMapMin && byt <= mpFixMapMax:
		n := int(byt & mpFixMapCounMask)
		return c.runMap(n)
	case byt >= mpFixArrayMin && byt <= mpFixArrayMax:
		n := int(byt & mpFixArrayCountMask)
		return c.runArray(n)
	case byt >= mpFixStrMin && byt <= mpFixStrMax:
		n := int(byt & mpFixstrCountMask)
		return c.readString(n)
	case byt >= mpNegativeFixMin && byt <= mpNegativeFixMax:
		return nil
	}

	switch byt {
	case mpNull, mpFalse, mpTrue:
		return nil
	case mpBin8:
		u, err := c.readUint8()
		if err != nil {
			return c.genErr(err)
		}
		return c.readString(int(u))
	case mpBin16:
		u, err := c.readUint16()
		if err != nil {
			return c.genErr(err)
		}
		if u <= 0xff {
			return c.genErrStr("short bin16 encoding")
		}
		return c.readString(int(u))
	case mpBin32:
		u, err := c.readUint32()
		if err != nil {
			return c.genErr(err)
		}
		if u <= 0xffff {
			return c.genErrStr("short bin32 encoding")
		}
		return c.readString(int(u))
	case mpExt8, mpExt16, mpExt32:
		return c.genErrStr("ext not allowed in canonical snowpack")
	case mpFloat, mpDouble:
		return c.genErrStr("float not allowed in canonical snowpack")
	case mpUint8:
		u, err := c.readUint8()
		if err != nil {
			return c.genErr(err)
		}
		if u <= 0x7f {
			return c.genErrStr("uint8 underflow")
		}
		return nil
	case mpUint16:
		u, err := c.readUint16()
		if err != nil {
			return c.genErr(err)
		}
		if u <= math.MaxUint8 {
			return c.genErrStr("uint16 underflow")
		}
		return nil
	case mpUint32:
		u, err := c.readUint32()
		if err != nil {
			return c.genErr(err)
		}
		if u <= math.MaxUint16 {
			return c.genErrStr("uint32 underflow")
		}
		return nil
	case mpUint64:
		u, err := c.readUint64()
		if err != nil {
			return c.genErr(err)
		}
		if u <= math.MaxUint32 {
			return c.genErrStr("uint64 underflow")
		}
		return nil
	case mpInt8:
		i, err := c.readInt8()
		if err != nil {
			return c.genErr(err)
		}
		if i >= 0 {
			return c.genErrStr("positive int8 encoding")
		}
		b := byte(mpNegativeFixMin)
		lim := int8(b)
		if i >= lim {
			return c.genErrStr("short int8 encoding")
		}
		return nil
	case mpInt16:
		i, err := c.readInt16()
		if err != nil {
			return c.genErr(err)
		}
		if i >= 0 {
			return c.genErrStr("positive int16 encoding")
		}
		if i >= math.MinInt8 {
			return c.genErrStr("short int16 encoding")
		}
		return nil
	case mpInt32:
		i, err := c.readInt32()
		if err != nil {
			return c.genErr(err)
		}
		if i >= 0 {
			return c.genErrStr("positive int32 encoding")
		}
		if i >= math.MinInt16 {
			return c.genErrStr("short int32 encoding")
		}
		return nil
	case mpInt64:
		i, err := c.readInt64()
		if err != nil {
			return c.genErr(err)
		}
		if i >= 0 {
			return c.genErrStr("positive int64 encoding")
		}
		if i >= math.MinInt32 {
			return c.genErrStr("short int64 encoding")
		}
		return nil
	case mpFixExt1, mpFixExt2, mpFixExt4, mpFixExt8, mpFixExt16:
		return c.genErrStr("fixext not allowed in canonical snowpack")
	case mpStr8:
		u, err := c.readUint8()
		if err != nil {
			return c.genErr(err)
		}
		if u <= 0x1f {
			return c.genErrStr("short str8 encoding")
		}
		return c.readString(int(u))
	case mpStr16:
		u, err := c.readUint16()
		if err != nil {
			return c.genErr(err)
		}
		if u <= math.MaxUint8 {
			return c.genErrStr("short str16 encoding")
		}
		return c.readString(int(u))
	case mpStr32:
		u, err := c.readUint32()
		if err != nil {
			return c.genErr(err)
		}
		if u <= math.MaxUint16 {
			return c.genErrStr("short str32 encoding")
		}
		return c.readString(int(u))
	case mpArray16:
		u, err := c.readUint16()
		if err != nil {
			return c.genErr(err)
		}
		if u <= 0x1f {
			return c.genErrStr("array16 where fixed array encoding is possible")
		}
		return c.runArray(int(u))
	case mpArray32:
		u, err := c.readUint32()
		if err != nil {
			return c.genErr(err)
		}
		if u <= math.MaxUint16 {
			return c.genErrStr("array32 where shorter array is possible")
		}
		return c.runArray(int(u))
	case mpMap16, mpMap32:
		return c.genErrStr("arbitrary maps not allowed")
	}

	return nil
}

func AssertCanonicalMsgpack(msg []byte) error {
	c := &canonicalizer{buf: msg}
	err := c.run()
	if err != nil {
		return err
	}
	if len(c.buf) != 0 {
		return CanonicalEncodingError{
			Err: errors.New("trailing junk at end of buffer"),
		}
	}
	return nil
}
