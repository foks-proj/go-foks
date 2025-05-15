package core

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBadSnowpackEncodings(t *testing.T) {

	tests := []struct {
		name     string
		encoding []byte
		err      error
	}{
		{
			name:     "junk-in-trunk",
			encoding: []byte{0x01, 0x02},
			err: CanonicalEncodingError{
				Err: errors.New("trailing junk at end of buffer"),
			},
		},
		{
			name:     "good-encoding",
			encoding: []byte{0x01},
		},
		{
			name:     "small-uint8",
			encoding: []byte{0xcc, 0x01},
			err: CanonicalEncodingError{
				Err: errors.New("uint8 underflow"),
			},
		},
		{
			name:     "small-uint16",
			encoding: []byte{0xcd, 0x00, 0x01},
			err: CanonicalEncodingError{
				Err: errors.New("uint16 underflow"),
			},
		},
		{
			name:     "small-uint32",
			encoding: []byte{0xce, 0x00, 0x00, 0xff, 0xff},
			err: CanonicalEncodingError{
				Err: errors.New("uint32 underflow"),
			},
		},
		{
			name:     "small-uint64",
			encoding: []byte{0xcf, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff},
			err: CanonicalEncodingError{
				Err: errors.New("uint64 underflow"),
			},
		},
		{
			name:     "good-uint64",
			encoding: []byte{0xcf, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff},
		},
		{
			name:     "short-array16",
			encoding: []byte{0xdc, 0x00, 0x02, 0x03, 0x04},
			err: CanonicalEncodingError{
				Err: errors.New("array16 where fixed array encoding is possible"),
			},
		},
		{
			name:     "short-array32",
			encoding: []byte{0xdd, 0x00, 0x00, 0x00, 0x01, 0x03},
			err: CanonicalEncodingError{
				Err: errors.New("array32 where shorter array is possible"),
			},
		},
		{
			name: "big-map",
			//  pp.pack([1,[2,[3,{a:4,b:5}]]])
			encoding: []byte{0x92, 0x01, 0x92, 0x02, 0x92, 0x03, 0x82, 0xa1, 0x61, 0x04, 0xa1, 0x62, 0x05},
			err: CanonicalEncodingError{
				Err: errors.New("map with more than one element not allowed"),
				Path: []StructStep{
					{Index: 1},
					{Index: 1},
					{Index: 1},
				},
			},
		},
		{
			name: "big-map-within-small-map",
			// pp.pack({a:[1,2,{a:3,b:4,c:5}]})
			encoding: []byte{0x81, 0xa1, 0x61, 0x93, 0x01, 0x02, 0x83, 0xa1, 0x61, 0x03, 0xa1, 0x62, 0x04, 0xa1, 0x63, 0x05},
			err: CanonicalEncodingError{
				Err: errors.New("map with more than one element not allowed"),
				Path: []StructStep{
					{Key: "a", Index: -1},
					{Index: 2},
				},
			},
		},
		{
			name:     "big-map-key",
			encoding: []byte{0x81, 0xd9, 0x2d, 0x61, 0x62, 0x61, 0x62, 0x63, 0x64, 0x63, 0x64, 0x65, 0x66, 0x65, 0x66, 0x67, 0x67, 0x68, 0x67, 0x68, 0x65, 0x69, 0x65, 0x69, 0x77, 0x6a, 0x65, 0x6f, 0x72, 0x69, 0x77, 0x6a, 0x65, 0x72, 0x6f, 0x69, 0x6a, 0x77, 0x65, 0x72, 0x6f, 0x69, 0x77, 0x65, 0x6a, 0x61, 0x73, 0x66, 0x0a},
			err: CanonicalEncodingError{
				Err: errors.New("invalid short string encoding for map key"),
			},
		},
		{
			name:     "positive-int-in-signed-int8",
			encoding: []byte{0xd0, 0x01},
			err: CanonicalEncodingError{
				Err: errors.New("positive int8 encoding"),
			},
		},
		{
			name:     "positive-int-in-signed-int16",
			encoding: []byte{0xd1, 0x00, 0x01},
			err: CanonicalEncodingError{
				Err: errors.New("positive int16 encoding"),
			},
		},
		{
			name:     "positive-int-in-signed-int32",
			encoding: []byte{0xd2, 0x00, 0x00, 0x00, 0x01},
			err: CanonicalEncodingError{
				Err: errors.New("positive int32 encoding"),
			},
		},
		{
			name:     "short-array16",
			encoding: []byte{0xdc, 0x00, 0x01, 0x02},
			err: CanonicalEncodingError{
				Err: errors.New("array16 where fixed array encoding is possible"),
			},
		},
		{
			name:     "short-array32",
			encoding: []byte{0xdd, 0x00, 0x00, 0x00, 0x01, 0x02},
			err: CanonicalEncodingError{
				Err: errors.New("array32 where shorter array is possible"),
			},
		},
		{
			name:     "short-int16-1",
			encoding: []byte{0xd1, 0xff, 0x87},
			err: CanonicalEncodingError{
				Err: errors.New("short int16 encoding"),
			},
		},
		{
			name:     "short-int16-2",
			encoding: []byte{0xd1, 0xff, 0x80},
			err: CanonicalEncodingError{
				Err: errors.New("short int16 encoding"),
			},
		},
		{
			name:     "valid-int16",
			encoding: []byte{0xd1, 0xff, 0x7f},
		},
		{
			name:     "short-int8-1",
			encoding: []byte{0xd0, 0xf5},
			err: CanonicalEncodingError{
				Err: errors.New("short int8 encoding"),
			},
		},
		{
			name:     "short-int8-2",
			encoding: []byte{0xd0, 0xff},
			err: CanonicalEncodingError{
				Err: errors.New("short int8 encoding"),
			},
		},
		{
			name:     "short-int8-3",
			encoding: []byte{0xd0, 0xe0},
			err: CanonicalEncodingError{
				Err: errors.New("short int8 encoding"),
			},
		},
		{
			name:     "valid-int8",
			encoding: []byte{0xd0, 0xdf},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := AssertCanonicalMsgpack(test.encoding)
			require.Equal(t, test.err, err)
		})
	}

}
