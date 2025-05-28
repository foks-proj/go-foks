// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// yk_full_demo.go
// End‑to‑end demo that exercises PIN‑gated signing scenarios on a factory‑fresh
// YubiKey using github.com/go-piv/piv-go/v2.
//
// Sequence:
//  1. Change the factory PIN (123456  →  654321).
//  2. Change the factory PUK (12345678 → 87654321).
//  3. Change the factory management key to a random value and store it *on card*
//     protected by the PIN (requires YubiKey ≥ 5.2).
//  4. Generate an EC‑P256 key in the **first retired slot** (0x82) with
//     PIN‑policy ONCE; demonstrate signing behaviour.
//  5. Generate another EC‑P256 key in the **second retired slot** (0x83) with
//     PIN‑policy ALWAYS; demonstrate signing behaviour.
//
// NOTE: The go‑piv/v2 API exposes StoreManagementKeyOnCard only in v2.4+. If you
// are on an older release, comment out that call and run `ykman piv access
// change-management-key --generate --protect` manually first.
// ---------------------------------------------------------------------------
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/keybase/go-codec/codec"
)

var pinOld = piv.DefaultPIN
var pinNew = "654321"

var pukOld = piv.DefaultPUK
var pukNew = "87654321"

func MainOld1() {

	yk := openFirstYubiKey()
	defer yk.Close()

	// dangerous to run this program, but i love danger
	must(yk.Reset())

	slotOnce, ok := piv.RetiredKeyManagementSlot(uint32(0x82))
	if !ok {
		log.Fatal("slot 0x82 not available")
	}

	slotAlways, ok := piv.RetiredKeyManagementSlot(uint32(0x83))
	if !ok {
		log.Fatal("slot 0x83 not available")
	}

	fmt.Println("Step 1: Change PIN →", pinNew)
	must(yk.SetPIN(pinOld, pinNew))

	fmt.Println("Step 2: Change PUK →", pukNew)
	must(yk.SetPUK(pukOld, pukNew))

	fmt.Println("Step 3: Rotate management key and store on card (PIN‑protected)…")
	var mgmtOld = piv.DefaultManagementKey
	var mgmtNew [24]byte
	_, _ = rand.Read(mgmtNew[:])
	mgmtNewSlice := mgmtNew[:]

	// Change the management key itself.
	must(yk.SetManagementKey(mgmtOld, mgmtNewSlice))

	// Store the key on card so future admin ops only need PIN.
	var md piv.Metadata
	md.ManagementKey = &mgmtNewSlice
	if err := yk.SetMetadata(mgmtNewSlice, &md); err != nil {
		log.Fatalf("StoreManagementKeyOnCard: %v", err)
	}
	fmt.Printf("  New management key: %s (keep it safe!)\n", hex.EncodeToString(mgmtNew[:]))

	// --------------------------- SLOT #1 (ONCE) ---------------------------
	fmt.Println("Step 4: Generate key in retired slot #1 (ONCE policy)…")
	pub1 := generateKey(yk, slotOnce, mgmtNew, piv.PINPolicyOnce)

	fmt.Println("Step 5: Try to sign — should fail (PIN not yet verified)…")
	if err := trySign(yk, slotOnce, pub1, nil); err == nil {
		log.Fatal("unexpected success: signing should fail before PIN verify")
	} else {
		fmt.Printf("  Expected failure: %v\n", err)
	}

	fmt.Println("Step 6: Verify PIN and sign twice…")
	must(yk.VerifyPIN(pinNew))
	must(trySign(yk, slotOnce, pub1, nil))
	must(trySign(yk, slotOnce, pub1, nil)) // second time succeeds without re‑PIN

	// --------------------------- SLOT #2 (ALWAYS) -------------------------
	fmt.Println("Step 7: Generate key in retired slot #2 (ALWAYS policy)…")
	pub2 := generateKey(yk, slotAlways, mgmtNew, piv.PINPolicyAlways)

	fmt.Println("Step 8: Try to sign — should fail (ALWAYS policy)…")
	if err := trySign(yk, slotAlways, pub2, nil); err == nil {
		log.Fatal("unexpected success: ALWAYS policy should require PIN each time")
	} else {
		fmt.Printf("  Expected failure: %v\n", err)
	}

	fmt.Println("Step 9: Verify PIN and sign once…")
	must(yk.VerifyPIN(pinNew))
	must(trySign(yk, slotAlways, pub2, nil))

	fmt.Println("Step 10: Verify PIN again and sign a second time…")
	must(yk.VerifyPIN(pinNew))
	must(trySign(yk, slotAlways, pub2, nil))

	fmt.Println("Step 11: Fail to sign since we forgot to verify PIN again…")
	if err := trySign(yk, slotAlways, pub2, nil); err == nil {
		log.Fatal("unexpected success: signing should fail after PIN verify")
	} else {
		fmt.Printf("  Expected failure: %v\n", err)
	}

	yk.Close()
	yk = openFirstYubiKey()
	defer yk.Close()

	fmt.Println("Step 12: Once works even after we close and reopen the YubiKey…")
	must(trySign(yk, slotOnce, pub1, nil)) // second time succeeds without re‑PIN

	fmt.Println("Demo completed successfully.")
}

// openFirstYubiKey opens the first attached YubiKey.
func openFirstYubiKey() *piv.YubiKey {
	readers, err := piv.Cards()
	must(err)
	for _, rdr := range readers {
		if strings.Contains(strings.ToLower(rdr), "yubikey") {
			yk, err := piv.Open(rdr)
			if err == nil {
				return yk
			}
		}
	}
	log.Fatal("no YubiKey found")
	return nil
}

// generateKey creates an EC‑P256 key in the given slot with the desired PIN policy.
func generateKey(yk *piv.YubiKey, slot piv.Slot, mgmtKey [24]byte, pol piv.PINPolicy) *ecdsa.PublicKey {
	tmpl := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   pol,
		TouchPolicy: piv.TouchPolicyNever,
	}
	pub, err := yk.GenerateKey(mgmtKey[:], slot, tmpl)
	must(err)
	return pub.(*ecdsa.PublicKey)
}

// trySign signs a fixed digest with the key in slot and returns any error.
func trySign(yk *piv.YubiKey, slot piv.Slot, pub *ecdsa.PublicKey, pin *string) error {
	signer, err := yk.PrivateKey(slot, pub, piv.KeyAuth{})
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte("demo message"))
	_, err = signer.(interface {
		Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
	}).Sign(rand.Reader, digest[:], nil)
	return err
}

// must is a tiny helper.
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func ff(doErr bool) (err error) {
	defer func() {
		tmp := errors.New("error B")
		if err == nil && tmp != nil {
			err = tmp
		}
	}()
	if doErr {
		err := errors.New("error A")
		return err
	}
	return nil
}

func Main4() {
	fmt.Printf("%v\n", ff(true))
	fmt.Printf("%v\n", ff(false))
}

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

func main() {

	i := 10
	s := "yo"

	o1 := &Obj1{
		F1: &i,
		F2: &s,
	}
	var mh codec.MsgpackHandle
	mh.WriteExt = true
	var buf []byte

	enc := codec.NewEncoderBytes(&buf, &mh)
	err := enc.Encode(o1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", buf)

	var o2 Obj2
	dec := codec.NewDecoderBytes(buf, &mh)
	err = dec.Decode(&o2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", o2)

}
