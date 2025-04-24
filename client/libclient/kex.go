// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type KexSecret struct {
	secret    proto.KexSecret
	sessionID proto.KexSessionID
	key       proto.SecretBoxKey
	sendSeqno proto.KexSeqNo
	recvSeqno proto.KexSeqNo
}

func generateKexSecret() (*KexSecret, error) {
	ret := KexSecret{}
	err := core.KexSeedHESPConfig.GenerateSecret(ret.secret[:])
	if err != nil {
		return nil, err
	}

	err = ret.fill()
	if err != nil {
		return nil, err
	}
	return &ret, err
}

func KexSecretFromKexHESP(w proto.KexHESP) (*KexSecret, error) {
	var ret KexSecret
	err := core.HESPToKexSecret(w, &ret.secret)
	if err != nil {
		return nil, err
	}
	err = ret.fill()
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func newKexSecret(s proto.KexSecret) (*KexSecret, error) {
	var ret KexSecret
	ret.secret = s
	err := ret.fill()
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (k *KexSecret) fill() error {
	var hmacKey proto.HMACKey
	copy(hmacKey[:], k.secret[:])
	deriveId := lcl.NewKexKeyDerivationDefault(lcl.KexDerivationType_SessionID)
	res, err := core.Hmac(&deriveId, &hmacKey)
	if err != nil {
		return err
	}
	copy(k.sessionID[:], (*res)[:])
	deriveKey := lcl.NewKexKeyDerivationDefault(lcl.KexDerivationType_SecretBoxKey)
	res, err = core.Hmac(&deriveKey, &hmacKey)
	if err != nil {
		return err
	}
	copy(k.key[:], (*res)[:])
	return nil
}

type KexBase struct {
	// input
	myKey core.PrivateSuiter
	ki    KexInterfacer

	// state
	mine      *KexSecret
	actorType rem.KexActorType

	agreedMu sync.Mutex
	agreed   *KexSecret

	link *proto.LinkOuter
}

type KexActor interface {
	run(ctx context.Context) error
	Base() *KexBase
}

var _ KexActor = (*KexProvisionee)(nil)
var _ KexActor = (*KexProvisioner)(nil)

type KexUIer interface {
	GetSessionFromUI(context.Context) (proto.KexSecret, func(context.Context, error), error)
	SendSessionToUI(context.Context, proto.KexSecret) error
	EndSessionExchange(context.Context, error) error
}

type KexNewDeviceKeyer interface {
	StoreNewDeviceKey(context context.Context, fqr proto.FQUserAndRole,
		ppe *lcl.KexPPE, selfTok proto.PermissionToken) error
}

type KexRouter interface {
	Send(context.Context, rem.SendArg) error
	Receive(context.Context, rem.ReceiveArg) (rem.KexWrapperMsg, error)
}

type KexLocalKeyer interface {
	FillChainer(context.Context, *proto.BaseChainer) error
	GetOrGeneratePUK(context.Context, core.RoleKey) (core.SharedPrivateSuiter, bool, error)
	GetAllDevicesForRole(context.Context, core.RoleKey) ([]core.PublicBoxer, error)
	CheckDeviceName(context.Context, *proto.DeviceLabelAndName) error
	GetKexPPE(context.Context) (*lcl.KexPPE, error)
}

type KexServer interface {
	ProvisionDevice(context.Context, rem.ProvisionDeviceArg) error
}

type KexInterfacer interface {
	UI() KexUIer
	Router() KexRouter
}

type KexFullInterfacer interface {
	KexInterfacer
	Keyer() KexLocalKeyer
	Server(ctx context.Context) (KexServer, error)
}

type KexProvisioner struct {
	KexBase

	// Provisioner does 2x work so needs 2 extra interfaces
	kfi KexFullInterfacer

	// input params
	role proto.Role
	uid  proto.UID
	host proto.HostID

	// state
	hello    *lcl.HelloMsg
	mlr      *core.MakeLinkRes
	pukBoxes *proto.SharedKeyBoxSet
	selfTok  proto.PermissionToken
}

func NewKexProvisioner(
	kfi KexFullInterfacer,
	uid proto.UID,
	host proto.HostID,
	role proto.Role,
	device core.PrivateSuiter,
) *KexProvisioner {
	return &KexProvisioner{
		KexBase: KexBase{
			myKey:     device,
			ki:        kfi,
			actorType: rem.KexActorType_Provisioner,
		},
		kfi:  kfi,
		uid:  uid,
		host: host,
		role: role,
	}
}

type KexProvisionee struct {
	KexBase

	// Check that a given host+user+role combo hasn't already signed up
	// locallly. If so, kill the kex. Otherwise, store the new device
	// to local storage. Note, we can't do this earlier since we don't
	// know the user's *UID* until a few rounds of kex (there is no
	// public mechanism to map username -> UID).
	ndk KexNewDeviceKeyer

	// input params
	dln proto.DeviceLabelAndName

	// state
	mySig *proto.Signature
	ppe   *lcl.KexPPE
	tok   *proto.PermissionToken

	TestErrorHook func() error
}

func (k *KexProvisionee) Base() *KexBase { return &k.KexBase }
func (k *KexProvisioner) Base() *KexBase { return &k.KexBase }

func NewKexProvisionee(
	ki KexInterfacer,
	kd KexNewDeviceKeyer,
	dln proto.DeviceLabelAndName,
	device core.PrivateSuiter,
) *KexProvisionee {
	return &KexProvisionee{
		KexBase: KexBase{
			myKey:     device,
			ki:        ki,
			actorType: rem.KexActorType_Provisionee,
		},
		ndk: kd,
		dln: dln,
	}
}

func (k *KexProvisioner) ImportProvisionee() (core.PublicSuiter, error) {
	return core.ImportKeySuite(k.hello.KeySuite, k.role, k.host)
}

func (k *KexBase) Link() *proto.LinkOuter { return k.link }

func (k *KexBase) makeSession(ctx context.Context) error {
	var err error
	k.mine, err = generateKexSecret()
	if err != nil {
		return err
	}
	return nil
}

func (k *KexBase) sendSessionToUI(ctx context.Context) error {
	err := k.ki.UI().SendSessionToUI(ctx, k.mine.secret)
	if err != nil {
		return err
	}
	return nil
}

func (k *KexSecret) wrap(m lcl.KexMsg, key core.EntityPrivate) (*rem.SendArg, error) {
	pub, err := key.EntityPublic()
	if err != nil {
		return nil, err
	}
	sender := pub.GetEntityID()
	clr := lcl.KexCleartext{
		SeesionID: k.sessionID,
		Seq:       k.sendSeqno,
		Sender:    sender,
		Msg:       m,
	}

	sbox, err := core.SealIntoSecretBox(&clr, &k.key)
	if err != nil {
		return nil, err
	}
	wmsg := rem.KexWrapperMsg{
		SessionID: k.sessionID,
		Sender:    sender,
		Seq:       k.sendSeqno,
		Payload:   *sbox,
	}
	sig, err := key.Sign(&wmsg)
	if err != nil {
		return nil, err
	}
	k.sendSeqno++
	ret := rem.SendArg{Sig: *sig, Msg: wmsg}
	return &ret, nil
}

func (k *KexProvisioner) sendStart(ctx context.Context) error {
	msg := lcl.NewKexMsgWithStart()
	return k.sendMsg(ctx, msg, k.mine)
}

func (k *KexBase) sendMsg(ctx context.Context, msg lcl.KexMsg, ks *KexSecret) error {
	if ks == nil {
		ks = k.getChannel()
	}
	if ks == nil {
		return core.InternalError("couldn't send due to no agreed upon kex channel")
	}
	sarg, err := ks.wrap(msg, k.myKey)
	if err != nil {
		return err
	}
	sarg.Actor = k.actorType
	err = k.ki.Router().Send(ctx, *sarg)
	if err != nil {
		return err
	}
	return nil
}

func (k *KexSecret) receiveArg(key core.EntityPrivate, ws waitStrategy) (*rem.ReceiveArg, error) {
	tmp, err := key.EntityPublic()
	if err != nil {
		return nil, err
	}
	ret := rem.ReceiveArg{
		Receiver:  tmp.GetEntityID(),
		SessionID: k.sessionID,
		Seq:       k.recvSeqno,
		PollWait:  1000 * 60 * 60,
	}
	if ws == failFast {
		ret.PollWait = 0
	}
	k.recvSeqno++
	return &ret, nil
}

func (k *KexSecret) unwrap(m rem.KexWrapperMsg, key core.EntityPrivate) (*lcl.KexMsg, error) {
	var clr lcl.KexCleartext
	err := core.OpenSecretBoxInto(&clr, m.Payload, &k.key)
	if err != nil {
		return nil, err
	}
	pub, err := key.EntityPublic()
	if err != nil {
		return nil, err
	}
	if !clr.SeesionID.Eq(&k.sessionID) {
		return nil, core.KexVerifyError("bad session ID on KEX packet")
	}
	if !clr.Sender.Eq(m.Sender) {
		return nil, core.KexVerifyError("bad sending in KEX pakcet")
	}
	if clr.Sender.Eq(pub.GetEntityID()) {
		return nil, core.KexVerifyError("reflection error")
	}
	if clr.Seq != m.Seq {
		return nil, core.KexVerifyError("bad seqno in KEX packet")
	}
	return &clr.Msg, nil
}

type waitStrategy int

const (
	failFast  waitStrategy = 0
	waitForIt waitStrategy = 1
)

func (k *KexProvisioner) getSessionFromUITryOnce(ctx context.Context) (*KexSecret, *lcl.HelloMsg, error) {
	raw, uiCallback, err := k.ki.UI().GetSessionFromUI(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Need to wrap in a func() to capture the err value as it updates
	// below. If we just do defer uiCallback(ctx, err), the err value
	// will be the one at the time of the defer, not the one at the
	// time of the call.
	defer func() { uiCallback(ctx, err) }()

	var ks *KexSecret
	ks, err = newKexSecret(raw)
	if err != nil {
		return nil, nil, err
	}

	// FailFast because on a valid session key, there should always be a message
	// waiting for us.
	var hello *lcl.HelloMsg
	hello, err = k.receiveAssertHello(ctx, ks, failFast)
	if err != nil {
		return nil, nil, err
	}

	return ks, hello, nil
}

func (k *KexBase) receiveAssert(ctx context.Context, ks *KexSecret, expected lcl.KexMsgType, ws waitStrategy) (*lcl.KexMsg, error) {
	if ks == nil {
		ks = k.getChannel()
	}

	rarg, err := ks.receiveArg(k.myKey, ws)
	if err != nil {
		return nil, err
	}
	rarg.Actor = k.actorType
	emsg, err := k.ki.Router().Receive(ctx, *rarg)
	if err != nil {
		return nil, err
	}
	msg, err := ks.unwrap(emsg, k.myKey)
	if err != nil {
		return nil, err
	}
	received, err := msg.GetT()
	if err != nil {
		return nil, err
	}
	if received == lcl.KexMsgType_Error {
		return nil, core.KexWrapperError{Err: core.StatusToError(msg.Error().Status)}
	}
	if received != expected {
		return nil, core.KexWrongMessageError{Expected: expected, Received: received}
	}
	return msg, nil
}

func (k *KexProvisioner) receiveAssertHello(ctx context.Context, ks *KexSecret, ws waitStrategy) (*lcl.HelloMsg, error) {
	msg, err := k.receiveAssert(ctx, ks, lcl.KexMsgType_Hello, ws)
	if err != nil {
		return nil, err
	}
	ret := msg.Hello()
	return &ret, nil
}

func (k *KexProvisioner) receiveAssertOkSigned(ctx context.Context, ks *KexSecret) (*lcl.OkSigned, error) {
	msg, err := k.receiveAssert(ctx, ks, lcl.KexMsgType_OkSigned, waitForIt)
	if err != nil {
		return nil, err
	}
	ret := msg.Oksigned()
	return &ret, nil
}

func (k *KexProvisioner) getSessionFromUI(ctx context.Context) (*KexSecret, *lcl.HelloMsg, error) {
	for {
		s, m, err := k.getSessionFromUITryOnce(ctx)
		if err == nil || err == context.Canceled {
			return s, m, err
		}
	}
}

func (k *KexProvisioner) receiveHelloOurChannel(ctx context.Context) (*lcl.HelloMsg, error) {
	return k.receiveAssertHello(ctx, k.mine, waitForIt)
}

func (k *KexProvisioner) receiveHello(ctx context.Context) error {

	ctx, doneFn := context.WithCancel(ctx)
	defer doneFn()

	// don't block the senders so we can reclaim their environments
	// after we exit (and are no longer listening)
	y2x := make(chan error, 1)
	x2y := make(chan error, 1)

	var hm1 *lcl.HelloMsg
	var hm2 *lcl.HelloMsg
	var theirSecret *KexSecret

	// Thread 1b: Get the secret from the UI and test that it works
	go func() {
		var err error
		theirSecret, hm2, err = k.getSessionFromUI(ctx)
		y2x <- err
	}()

	// Thread 1a: Get the secret from the server via our channel
	go func() {
		var err error
		hm1, err = k.receiveHelloOurChannel(ctx)
		x2y <- err
	}()

	var err error

	select {
	case err = <-x2y:
		if err == nil {
			k.setChannel(k.mine)
			k.hello = hm1
		}
	case err = <-y2x:
		if err == nil {
			k.setChannel(theirSecret)
			k.hello = hm2
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		return err
	}
	err = k.ki.UI().EndSessionExchange(ctx, err)
	if err != nil {
		return err
	}
	return nil
}

type kexLinkGenerator struct {
	klk          KexLocalKeyer
	existingPriv core.PrivateSuiter
	newPub       core.PublicSuiter
	role         proto.Role
	uid          proto.UID
	host         proto.HostID
	devLabel     proto.DeviceLabel
	subkey       core.EntityPrivate
}

type kexGenerateLinkRes struct {
	mlr      *core.MakeLinkRes
	pukBoxes *proto.SharedKeyBoxSet
}

func (k *kexLinkGenerator) gen(ctx context.Context) (*kexGenerateLinkRes, error) {

	var chainer proto.HidingChainer
	err := k.klk.FillChainer(ctx, &chainer.Base)
	if err != nil {
		return nil, err
	}
	rk, err := core.ImportRole(k.role)
	if err != nil {
		return nil, err
	}
	puk, isGen, err := k.klk.GetOrGeneratePUK(ctx, *rk)
	if err != nil {
		return nil, err
	}
	var newPuk core.SharedPrivateSuiter
	if isGen {
		newPuk = puk
	}

	existingPub, err := k.existingPriv.Publicize(&k.host)
	if err != nil {
		return nil, err
	}

	mlr, err := core.MakeProvisionLinkWithPub(
		k.uid,
		k.host,
		existingPub,
		k.newPub,
		k.role,
		newPuk,
		k.devLabel,
		chainer.Base.Seqno,
		*chainer.Base.Prev,
		chainer.Base.Root,
		k.subkey,
	)
	if err != nil {
		return nil, err
	}

	ret := &kexGenerateLinkRes{
		mlr: mlr,
	}

	boxFor := []core.PublicBoxer{k.newPub}
	if isGen {
		keys, err := k.klk.GetAllDevicesForRole(ctx, *rk)
		if err != nil {
			return nil, err
		}
		boxFor = append(boxFor, keys...)
	}

	skb, err := core.NewSharedKeyBoxer(k.host, k.existingPriv)
	if err != nil {
		return nil, err
	}
	for _, dev := range boxFor {
		err := skb.Box(puk, dev)
		if err != nil {
			return nil, err
		}
	}
	ret.pukBoxes, err = skb.Finish()
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (k *KexProvisioner) generateLink(ctx context.Context) error {
	if k.hello == nil {
		return core.InternalError("expected kex hello message, but had none")
	}
	provisionee, err := k.ImportProvisionee()
	if err != nil {
		return err
	}

	kg := kexLinkGenerator{
		klk:          k.kfi.Keyer(),
		existingPriv: k.myKey,
		newPub:       provisionee,
		role:         k.role,
		uid:          k.uid,
		host:         k.host,
		devLabel:     k.hello.Dln.Label,
	}
	res, err := kg.gen(ctx)
	if err != nil {
		return err
	}
	k.mlr = res.mlr
	k.link = res.mlr.Link
	res.mlr.Link = nil // so we don't mistakenly use it
	k.pukBoxes = res.pukBoxes
	return nil
}

func (k *KexProvisioner) sendLink(ctx context.Context) error {
	ppe, err := k.kfi.Keyer().GetKexPPE(ctx)
	if err != nil {
		return err
	}
	tok, err := core.NewPermissionToken()
	if err != nil {
		return err
	}
	k.selfTok = tok
	err = k.sendMsg(
		ctx,
		lcl.NewKexMsgWithPleasesign(
			lcl.PleaseSign{
				Link: *k.link,
				Ppe:  ppe,
				Tok:  k.selfTok,
			},
		),
		nil,
	)
	return err
}

func (k *KexProvisioner) checkProvisoneeSig(
	ctx context.Context,
	lov1 *proto.LinkOuterV1,
	sig proto.Signature,
) error {
	key, err := k.ImportProvisionee()
	if err != nil {
		return err
	}
	err = key.Verify(sig, lov1)
	if err != nil {
		return err
	}
	return nil
}

func (k *KexProvisioner) receiveSig(ctx context.Context) error {
	oks, err := k.receiveAssertOkSigned(ctx, k.getChannel())
	if err != nil {
		return err
	}

	sig := oks.Sig

	lov1, err := core.OpenLinkV1(k.link)
	if err != nil {
		return err
	}

	err = k.checkProvisoneeSig(ctx, lov1, sig)
	if err != nil {
		return err
	}

	lov1.Signatures = append(lov1.Signatures, sig)

	tmp := proto.NewLinkOuterWithV1(*lov1)
	k.link = &tmp

	return nil
}

func (k *KexProvisioner) sign(ctx context.Context) error {
	link, err := core.CountersignProvisionLink(k.link, k.myKey)
	if err != nil {
		return err
	}
	k.link = link
	return nil
}

func (k *KexProvisionee) sign(ctx context.Context) error {
	sig, _, err := core.CountersignProvisionLinkReturnSig(k.link, k.myKey)
	if err != nil {
		return err
	}
	k.mySig = sig
	return nil
}

func (k *KexProvisioner) post(ctx context.Context) error {

	var hepks proto.HEPKSet
	hepks.Push(k.hello.KeySuite.Hepk)

	arg := rem.ProvisionDeviceArg{
		Link:     *k.link,
		PukBoxes: *k.pukBoxes,
		Dlnc: rem.DeviceLabelNameAndCommitmentKey{
			Dln:           k.hello.Dln,
			CommitmentKey: *k.mlr.DevNameCommitmentKey,
		},
		NextTreeLocation: *k.mlr.NextTreeLocation,
		SelfToken:        k.selfTok,
		Hepks:            hepks,
	}
	srv, err := k.kfi.Server(ctx)
	if err != nil {
		return err
	}
	return srv.ProvisionDevice(ctx, arg)
}

func (k *KexProvisioner) Link() *proto.LinkOuter {
	return k.link
}

func (k *KexProvisioner) sendDone(ctx context.Context) error {
	return k.sendMsg(ctx, lcl.NewKexMsgWithDone(), nil)
}

func (k *KexProvisioner) checkDeviceName(ctx context.Context) error {
	err := k.kfi.Keyer().CheckDeviceName(ctx, &k.hello.Dln)
	if err != nil {
		return err
	}
	return nil
}

func (k *KexProvisioner) DeviceLabelAndName() *proto.DeviceLabelAndName {
	if k.hello == nil {
		return nil
	}
	return &k.hello.Dln
}

func (k *KexBase) MyKey() core.PrivateSuiter {
	return k.myKey
}

func (k *KexProvisioner) run(ctx context.Context) error {

	err := k.makeSession(ctx)
	if err != nil {
		return err
	}

	err = k.sendStart(ctx)
	if err != nil {
		return err
	}

	err = k.sendSessionToUI(ctx)
	if err != nil {
		return err
	}

	err = k.receiveHello(ctx)
	if err != nil {
		return err
	}

	err = k.checkDeviceName(ctx)
	if err != nil {
		return err
	}

	err = k.generateLink(ctx)
	if err != nil {
		return err
	}

	err = k.sendLink(ctx)
	if err != nil {
		return err
	}

	err = k.receiveSig(ctx)
	if err != nil {
		return err
	}

	err = k.sign(ctx)
	if err != nil {
		return err
	}

	err = k.post(ctx)
	if err != nil {
		return err
	}

	err = k.sendDone(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (k *KexProvisionee) helloMsg(ctx context.Context) (*lcl.HelloMsg, error) {
	ks, err := k.myKey.ExportKeySuite()
	if err != nil {
		return nil, err
	}
	ret := lcl.HelloMsg{
		Dln:      k.dln,
		KeySuite: *ks,
	}
	return &ret, nil
}

func (k *KexBase) setChannel(ks *KexSecret) {
	k.agreedMu.Lock()
	defer k.agreedMu.Unlock()
	k.agreed = ks
}

func (k *KexBase) getChannel() *KexSecret {
	k.agreedMu.Lock()
	defer k.agreedMu.Unlock()
	return k.agreed
}

func (k *KexProvisionee) sendHello(ctx context.Context, ks *KexSecret) error {
	hmsg, err := k.helloMsg(ctx)
	if err != nil {
		return err
	}
	if ks == nil {
		return core.InternalError("kex error: no kex channel to sendHello on")
	}
	err = k.sendMsg(ctx, lcl.NewKexMsgWithHello(*hmsg), ks)
	return err
}

func (k *KexProvisionee) sendOkSigned(ctx context.Context) error {
	return k.sendMsg(
		ctx,
		lcl.NewKexMsgWithOksigned(
			lcl.OkSigned{
				Sig: *k.mySig,
			},
		),
		k.getChannel(),
	)
}

func (k *KexProvisionee) receivePleaseSign(ctx context.Context, ks *KexSecret) (*lcl.PleaseSign, error) {
	msg, err := k.receiveAssert(ctx, ks, lcl.KexMsgType_PleaseSign, waitForIt)
	if err != nil {
		return nil, err
	}
	ret := msg.Pleasesign()
	k.ppe = ret.Ppe
	k.tok = &ret.Tok
	return &ret, nil
}

func (k *KexProvisionee) getSessionFromUITryOnce(ctx context.Context) (*KexSecret, *lcl.PleaseSign, error) {
	raw, uiCallback, err := k.ki.UI().GetSessionFromUI(ctx)
	if err != nil {
		return nil, nil, err
	}
	ks, err := newKexSecret(raw)
	if err != nil {
		uiCallback(ctx, err)
		return nil, nil, err
	}
	_, err = k.receiveAssert(ctx, ks, lcl.KexMsgType_Start, failFast)
	if err != nil {
		uiCallback(ctx, err)
		return nil, nil, err
	}

	// once we get past the receiveAssert without error, then likely the input is
	// correct.
	uiCallback(ctx, nil)

	err = k.sendHello(ctx, ks)
	if err != nil {
		return nil, nil, err
	}
	ps, err := k.receivePleaseSign(ctx, ks)
	if err != nil {
		return nil, nil, err
	}
	return ks, ps, nil
}

func (k *KexProvisionee) getSessionFromUI(ctx context.Context) (*KexSecret, *lcl.PleaseSign, error) {

	isBreakError := func(e error) bool {
		if e == nil || e == context.Canceled {
			return true
		}
		if _, isKexError := e.(core.KexWrapperError); isKexError {
			return true
		}
		return false
	}

	for {
		s, m, err := k.getSessionFromUITryOnce(ctx)
		if isBreakError(err) {
			return s, m, err
		}
	}
}

func (k *KexProvisionee) receiveLink(ctx context.Context) error {
	ctx, doneFn := context.WithCancel(ctx)
	defer doneFn()

	y2x := make(chan error, 1)
	x2y := make(chan error, 1)
	var ps1 *lcl.PleaseSign
	var ps2 *lcl.PleaseSign
	var theirs *KexSecret

	go func() {
		var err error
		ps1, err = k.receivePleaseSign(ctx, k.mine)
		y2x <- err
	}()

	go func() {
		var err error
		theirs, ps2, err = k.getSessionFromUI(ctx)
		x2y <- err
	}()

	var err error
	select {
	case err = <-y2x:
		if err == nil {
			k.setChannel(k.mine)
			k.link = &ps1.Link
		}
	case err = <-x2y:
		if err == nil {
			k.setChannel(theirs)
			k.link = &ps2.Link
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		return err
	}

	err = k.ki.UI().EndSessionExchange(ctx, err)
	if err != nil {
		return err
	}
	return nil
}

func (k *KexProvisionee) receiveDone(ctx context.Context) error {
	_, err := k.receiveAssert(ctx, nil, lcl.KexMsgType_Done, waitForIt)
	return err
}

func (k *KexProvisionee) maybeErrorInTest(ctx context.Context) error {
	if k.TestErrorHook == nil {
		return nil
	}
	return k.TestErrorHook()
}

func (k *KexBase) groupChange() (*proto.GroupChange, error) {
	v, err := k.link.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.LinkVersion_V1 {
		return nil, core.VersionNotSupportedError("link from future")
	}
	blob := k.link.V1().Inner
	inner, err := blob.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return nil, err
	}
	typ, err := inner.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.LinkType_GROUP_CHANGE {
		return nil, core.VersionNotSupportedError("link not of type group change")
	}
	ch := inner.GroupChange()
	return &ch, nil
}

func (k *KexProvisionee) storeDeviceKey(ctx context.Context) error {
	gc, err := k.groupChange()
	if err != nil {
		return err
	}
	if len(gc.Changes) != 1 {
		return core.LinkError("can only support 1 change in a kex link")
	}
	chng := gc.Changes[0]
	uid, err := gc.Entity.Entity.ToUID()
	if err != nil {
		return err
	}
	role := chng.DstRole
	host := gc.Entity.Host

	return k.ndk.StoreNewDeviceKey(ctx,
		proto.FQUserAndRole{
			Fqu: proto.FQUser{
				Uid:    uid,
				HostID: host,
			},
			Role: role,
		},
		k.ppe,
		*k.tok,
	)
}

func (k *KexProvisionee) run(ctx context.Context) error {

	err := k.makeSession(ctx)
	if err != nil {
		return err
	}
	err = k.sendHello(ctx, k.mine)
	if err != nil {
		return err
	}

	err = k.sendSessionToUI(ctx)
	if err != nil {
		return err
	}

	err = k.receiveLink(ctx)
	if err != nil {
		return err
	}

	err = k.storeDeviceKey(ctx)
	if err != nil {
		return err
	}

	err = k.maybeErrorInTest(ctx)
	if err != nil {
		return err
	}

	err = k.sign(ctx)
	if err != nil {
		return err
	}

	err = k.sendOkSigned(ctx)
	if err != nil {
		return err
	}

	err = k.receiveDone(ctx)
	if err != nil {
		return err
	}

	return nil
}

func RunKex(ctx context.Context, r KexActor, d time.Duration) error {
	ctx, rfn := context.WithTimeout(ctx, d)
	defer rfn()

	err := r.run(ctx)
	if err == nil {
		return nil
	}

	// If we died because of a wrapped error, that means the *other* side
	// told us it was done, and we should stop / bail out. So there is
	// no reason to send that message back to the other side.
	if _, isWrappedError := err.(core.KexWrapperError); isWrappedError {
		return err
	}

	emsg := lcl.NewKexMsgWithError(lcl.KexError{
		Status: core.ErrorToStatus(err),
	})
	b := r.Base()

	// For now, ignore any errors coming out of here.
	_ = b.sendMsg(ctx, emsg, b.getChannel())

	return err
}
