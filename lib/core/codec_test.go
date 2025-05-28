package core

import (
	"testing"

	"github.com/keybase/go-codec/codec"
	"github.com/stretchr/testify/require"
)

// Test that if you have am object Foo, and add a field to it, that new new encoders can
// still decode the old object. And vice versa.
func TestCodecForwardsCompatible(t *testing.T) {

	type Obj1 struct {
		_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
		F1      *int
		F2      *string
	}

	type Obj2 struct {
		_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
		F1      *int
		F2      *string
		F3      *int
	}

	i := 10
	s := "yo"

	o1 := Obj1{
		F1: &i, F2: &s,
	}

	mh := Codec()
	var buf []byte
	enc := codec.NewEncoderBytes(&buf, mh)
	err := enc.Encode(&o1)
	require.NoError(t, err)

	var o2 Obj2
	dec := codec.NewDecoderBytes(buf, mh)
	err = dec.Decode(&o2)
	require.NoError(t, err)

	require.Nil(t, o2.F3)
	require.Equal(t, i, *o2.F1)
	require.Equal(t, s, *o2.F2)

	var buf2 []byte
	i3 := 40
	o2.F3 = &i3

	enc = codec.NewEncoderBytes(&buf2, mh)
	err = enc.Encode(&o2)
	require.NoError(t, err)

	var o3 Obj1
	dec = codec.NewDecoderBytes(buf2, mh)
	err = dec.Decode(&o3)
	require.NoError(t, err)
	require.Equal(t, i, *o3.F1)
	require.Equal(t, s, *o3.F2)

}
