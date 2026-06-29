// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/ecdsa"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

// HEPK = Hybrid Encrypted Public Key

type HEPKWrapper struct {
	*proto.HEPK
}

func HEPK(h *proto.HEPK) HEPKWrapper {
	return HEPKWrapper{h}
}

func (h HEPKWrapper) Obj() *proto.HEPK {
	return h.HEPK
}

func (h HEPKWrapper) Fingerprint() (*proto.HEPKFingerprint, error) {
	var ret proto.HEPKFingerprint
	err := PrefixedHashInto(h.HEPK, ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (h HEPKWrapper) Open() (*proto.HEPKv1, error) {
	v, err := h.GetV()
	if err != nil {
		return nil, err
	}
	if v == proto.HEPKVersion_None {
		return nil, InternalError("HEPK uninitialized")
	}
	if v != proto.HEPKVersion_V1 {
		return nil, VersionNotSupportedError("HEPK from future")
	}
	ret := h.V1()
	return &ret, nil
}

func (h HEPKWrapper) ExtractCurve25519() (*proto.Curve25519PublicKey, error) {
	v1, err := h.Open()
	if err != nil {
		return nil, err
	}
	typ, err := v1.Classical.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.DHType_Curve25519 {
		return nil, KeyImportError("bad dh type")
	}
	ret := v1.Classical.Curve25519()
	return &ret, nil
}

func (h HEPKWrapper) ExtractP256() (*ecdsa.PublicKey, error) {
	v1, err := h.Open()
	if err != nil {
		return nil, err
	}
	typ, err := v1.Classical.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.DHType_P256 {
		return nil, KeyImportError("bad dh type")
	}
	ret, err := v1.Classical.P256().ImportToECDSAPublic()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (h HEPKWrapper) AssertFingerprint(f *proto.HEPKFingerprint) error {
	fp, err := h.Fingerprint()
	if err != nil {
		return err
	}
	if !fp.Eq(f) {
		return HEPKFingerprintError{}
	}
	return nil
}

func (h HEPKWrapper) DHPublicKey() (*proto.DHPublicKey, error) {
	v1, err := h.Open()
	if err != nil {
		return nil, err
	}
	ret := v1.Classical
	return &ret, nil
}

func (h HEPKWrapper) KemEncapKey() (*proto.KemEncapKey, error) {
	v1, err := h.Open()
	if err != nil {
		return nil, err
	}
	ret := v1.Pqkem
	return &ret, nil
}

type HEPKSet struct {
	m map[proto.HEPKFingerprint]HEPKWrapper
}

func NewHEPKSet() *HEPKSet {
	return &HEPKSet{m: make(map[proto.HEPKFingerprint]HEPKWrapper)}
}

type HEPKExporter interface {
	ExportHEPK() (*proto.HEPK, error)
}

func (s *HEPKSet) AddHEPKExporter(h HEPKExporter) error {
	hpk, err := h.ExportHEPK()
	if err != nil {
		return err
	}
	return s.Add(*hpk)
}

func (s *HEPKSet) Add(h proto.HEPK) error {
	if s.m == nil {
		s.m = make(map[proto.HEPKFingerprint]HEPKWrapper)
	}
	w := HEPK(&h)
	fp, err := w.Fingerprint()
	if err != nil {
		return err
	}
	s.m[*fp] = w
	return nil
}

func ImportHEPKSet(hs *proto.HEPKSet) (*HEPKSet, error) {
	ret := NewHEPKSet()
	if hs != nil {
		for _, v := range hs.V {
			tmp := v
			w := HEPK(&tmp)
			fp, err := w.Fingerprint()
			if err != nil {
				return nil, err
			}
			ret.m[*fp] = w
		}
	}
	return ret, nil
}

func (h *HEPKSet) Lookup(f *proto.HEPKFingerprint) (HEPKWrapper, bool) {
	if h == nil || h.m == nil {
		return HEPKWrapper{}, false
	}
	ret, ok := h.m[*f]
	return ret, ok
}

func (h *HEPKSet) Merge(o *HEPKSet) *HEPKSet {
	if (h == nil || h.m == nil) && (o == nil || o.m == nil) {
		return NewHEPKSet()
	}
	if h == nil || h.m == nil {
		return o
	}
	for k, v := range o.m {
		v := v
		h.m[k] = v
	}
	return h
}

func (h *HEPKSet) MergeInto(o *HEPKSet) {
	if o == nil {
		return
	}
	for k, v := range h.m {
		v := v
		o.m[k] = v
	}
}

func (h *HEPKSet) Export() proto.HEPKSet {
	ret := proto.HEPKSet{
		V: make([]proto.HEPK, 0, len(h.m)),
	}
	if h.m != nil {
		for _, v := range h.m {
			ret.V = append(ret.V, *v.Obj())
		}
	}
	return ret
}

func (h *HEPKSet) AddSet(s proto.HEPKSet) error {
	for _, v := range s.V {
		if err := h.Add(v); err != nil {
			return err
		}
	}
	return nil
}
