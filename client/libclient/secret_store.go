// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type SecretStore struct {

	// protect against writes or reads from multiple threads
	sync.RWMutex

	// filename path to where this file is stored
	path string

	// Data that we've read off the disk, and intend to write back
	data *lcl.SecretStoreV2

	// if we've made changes to the in-memory copy of the data
	dirty bool
}

func NewSecretStore(p string) *SecretStore {
	return &SecretStore{
		path: p,
	}
}

func newSecretStoreProto() (*lcl.SecretStoreV2, error) {
	id, err := proto.RandomID16er[proto.LocalInstanceID]()
	if err != nil {
		return nil, err
	}
	return &lcl.SecretStoreV2{
		Id: *id,
	}, nil
}

func (s *SecretStore) LocalInstanceID() (*proto.LocalInstanceID, error) {
	s.RLock()
	defer s.RUnlock()
	if s.data == nil {
		return nil, core.KeyNotFoundError{Which: "local instance id"}
	}
	return &s.data.Id, nil
}

// LoadOrCreate either Loads() an existing SecretStore or will "create" one by not dying on
// failing to open the file. It might, in the future, also check that we can touch a file in
// target directory, since otherwise, we're going to get a failure on Save(). That might be OK
// anyways, depending on how the caller is configured.
func (s *SecretStore) LoadOrCreate(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	err := s.loadWithLock(ctx)
	if err == nil {
		return nil
	}
	if _, ok := err.(*fs.PathError); !ok {
		return err
	}
	dat, err := newSecretStoreProto()
	if err != nil {
		return err
	}
	s.data = dat
	s.dirty = true

	return err
}

func (s *SecretStore) Load(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()
	return s.loadWithLock(ctx)
}

func (s *SecretStore) loadWithLock(ctx context.Context) error {

	dat, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var tmp lcl.SecretStore
	err = core.DecodeFromBytes(&tmp, dat)
	if err != nil {
		return err
	}
	v, err := tmp.GetV()
	if err != nil {
		return err
	}
	switch v {
	case lcl.SecretStoreVersion_V2:
		tmpv2 := tmp.V2()
		s.data = &tmpv2
	default:
		return core.VersionNotSupportedError(fmt.Sprintf("secret store version from the future (%d) and can only support v2", v))
	}

	return nil
}

// attempt to overwrite the file with noise
func overwrite(fh *os.File) error {
	pos, err := fh.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	b := make([]byte, pos)
	_, err = rand.Read(b)
	if err != nil {
		return err
	}
	_, err = fh.Seek(0, 0)
	if err != nil {
		return err
	}
	_, err = fh.Write(b)
	return err

}

func cleanup(fh *os.File) error {
	// TODO: Warn! We need to set up some debugging, etc, to handle both errors that
	// we are ignoring
	err := overwrite(fh)
	if err != nil {
		return err
	}
	err = os.Remove(fh.Name())
	if err != nil {
		return err
	}
	return nil
}

func (s *SecretStore) exportData() ([]byte, error) {
	var err error
	if s.data == nil {
		s.data, err = newSecretStoreProto()
		if err != nil {
			return nil, err
		}
	}
	tmp := lcl.NewSecretStoreWithV2(*s.data)
	ret, err := core.EncodeToBytes(&tmp)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *SecretStore) Save(ctx context.Context) error {
	// Need a read/write lock so we can unset the dirty bit at the end of the method
	s.Lock()
	defer s.Unlock()
	return s.saveWithLock(ctx)
}

func (s *SecretStore) Dir() string {
	return filepath.Dir(s.path)
}

func (s *SecretStore) Export() *lcl.SecretStore {
	if s.data == nil {
		return nil
	}
	ret := lcl.NewSecretStoreWithV2(*s.data)
	return &ret
}

func (s *SecretStore) saveWithLock(ctx context.Context) (err error) {

	if !s.dirty {
		return nil
	}

	dir := filepath.Dir(s.path)
	filename := filepath.Base(s.path)

	if filename == "" || filename == "." {
		return core.ConfigError("bad secret store file name given")
	}

	fh, err := os.CreateTemp(dir, filename+".")
	if err != nil {
		return err
	}

	// By default, unlink and overwrite this sensitive file. if we hit success, then no need to.
	success := false
	defer func() {
		if !success {
			tmp := cleanup(fh)
			if err == nil && tmp != nil {
				err = tmp
			}
		}
	}()

	dat, err := s.exportData()
	if err != nil {
		return err
	}

	_, err = fh.Write(dat)
	if err != nil {
		return err
	}

	err = fh.Close()
	if err != nil {
		return err
	}

	tmpname := fh.Name()
	err = os.Rename(tmpname, s.path)
	if err != nil {
		return err
	}
	success = true
	s.dirty = false
	return nil
}

type SecretStoreGetOpts struct {
	ByDeviceID    bool
	NoProvisional bool
}

type SecretStoreGetArgs struct {
	Fqu      proto.FQUser
	Role     proto.Role
	DeviceID proto.DeviceID
	Opts     SecretStoreGetOpts
}

func (s *SecretStore) Get(
	args SecretStoreGetArgs,
) (
	*lcl.LabeledSecretKeyBundle,
	error,
) {
	s.RLock()
	defer s.RUnlock()

	if args.Opts.ByDeviceID {
		ret, _ := s.lookupWithLockByDeviceID(args.Fqu, args.DeviceID)
		return ret, nil
	}
	ret, _, err := s.lookupWithLock(args.Fqu, args.Role, args.Opts.NoProvisional)
	return ret, err
}

func (s *SecretStore) ListAll() ([]lcl.FQUserRoleAndDeviceID, error) {
	s.RLock()
	defer s.RUnlock()
	var ret []lcl.FQUserRoleAndDeviceID
	for _, k := range s.data.Keys {
		ret = append(ret, lcl.FQUserRoleAndDeviceID{
			Fqur:  k.Fqur,
			KeyID: k.KeyID,
		})
	}
	return ret, nil
}

func (s *SecretStore) Delete(fqu proto.FQUser, role proto.Role, did proto.DeviceID) error {
	s.Lock()
	defer s.Unlock()
	row, pos, err := s.lookupWithLock(fqu, role, false)
	if err != nil {
		return err
	}
	if pos < 0 {
		return core.KeyNotFoundError{Which: "devkey"}
	}
	if !did.Eq(row.KeyID) {
		return core.KeyMismatchError{}
	}
	s.data.Keys = append(s.data.Keys[:pos], s.data.Keys[pos+1:]...)
	s.dirty = true
	return nil
}

func (s *SecretStore) foreachMatchedRowLocked(
	fqu proto.FQUser,
	whitelist []proto.DeviceID,
	fn func(*lcl.LabeledSecretKeyBundle) (bool, error),
) error {
	if s.data == nil {
		return nil
	}
	set := make(map[proto.FixedEntityID]bool)
	for _, v := range whitelist {
		fid, err := v.EntityID().Fixed()
		if err != nil {
			return nil
		}
		set[fid] = true
	}

	for i, row := range s.data.Keys {
		if !row.Fqur.Fqu.Eq(fqu) {
			continue
		}
		key, err := row.KeyID.EntityID().Fixed()
		if err != nil {
			return err
		}
		if set[key] {
			mut, err := fn(&row)
			if err != nil {
				return err
			}
			if mut {
				s.data.Keys[i] = row
			}

		}
	}
	return nil
}

func (s *SecretStore) ClearProvisionalBits(
	ctx context.Context,
	u proto.FQUser,
	devices []proto.DeviceID,
) (
	int,
	error,
) {
	s.Lock()
	defer s.Unlock()

	var n int
	err := s.foreachMatchedRowLocked(u, devices, func(row *lcl.LabeledSecretKeyBundle) (bool, error) {
		var mut bool
		if row.Provisional {
			row.Provisional = false
			n++
			mut = true
		}
		return mut, nil
	})
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}

	s.dirty = true

	err = s.saveWithLock(ctx)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SecretStore) FilterDeviceIDs(
	fqu proto.FQUser,
	whitelist []proto.DeviceID,
) (
	[]proto.DeviceID,
	error,
) {
	s.RLock()
	defer s.RUnlock()

	var ret []proto.DeviceID
	err := s.foreachMatchedRowLocked(fqu, whitelist, func(row *lcl.LabeledSecretKeyBundle) (bool, error) {
		ret = append(ret, row.KeyID)
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (s *SecretStore) lookupWithLockByDeviceID(
	fqu proto.FQUser,
	did proto.DeviceID,
) (*lcl.LabeledSecretKeyBundle, int) {
	if s.data == nil {
		return nil, -1
	}
	for i, v := range s.data.Keys {
		if v.KeyID.Eq(did) && v.Fqur.Fqu.Eq(fqu) {
			return &v, i
		}
	}
	return nil, -1
}

func (s *SecretStore) lookupWithLock(
	fqu proto.FQUser,
	role proto.Role,
	noProvsionalDevices bool,
) (
	*lcl.LabeledSecretKeyBundle,
	int,
	error,
) {
	if s.data == nil {
		return nil, -1, nil
	}

	// iterate in reverse order so we get the must recent entry.
	// if we ever failed to provision, and try again, the second entry will
	// be the one that works, The first will be dead
	for i := len(s.data.Keys) - 1; i >= 0; i-- {
		v := s.data.Keys[i]
		roleEq, err := v.Fqur.Role.Eq(role)
		if err != nil {
			return nil, -1, err
		}
		if !roleEq || !v.Fqur.Fqu.Eq(fqu) {
			continue
		}
		if v.Provisional && noProvsionalDevices {
			continue
		}
		return &v, i, nil
	}
	return nil, -1, nil
}

func (s *SecretStore) Put(row lcl.LabeledSecretKeyBundle) error {
	s.Lock()
	defer s.Unlock()
	ex, _ := s.lookupWithLockByDeviceID(row.Fqur.Fqu, row.KeyID)
	if ex != nil {
		return core.SecretKeyExistsError{}
	}
	tmp, _, err := s.lookupWithLock(row.Fqur.Fqu, row.Fqur.Role, true)
	if err != nil {
		return err
	}
	if tmp != nil {
		return core.SecretKeyExistsError{}
	}
	row.Ctime = proto.Now()
	row.Mtime = row.Ctime
	row.MinorVersion = CurrentSecretKeyRowMinorVersion
	s.data.Keys = append(s.data.Keys, row)
	s.dirty = true
	return nil
}

func (s *SecretStore) Update(row lcl.LabeledSecretKeyBundle) error {
	s.Lock()
	defer s.Unlock()
	_, err := s.updateWithLock(row)
	return err
}

const CurrentSecretKeyRowMinorVersion = lcl.SecretKeyBundleMinorVersion(1)

func (s *SecretStore) updateWithLock(row lcl.LabeledSecretKeyBundle) (func(), error) {
	_, pos := s.lookupWithLockByDeviceID(row.Fqur.Fqu, row.KeyID)
	if pos < 0 {
		return nil, core.KeyNotFoundError{Which: "secret devkey"}
	}
	row.Mtime = proto.Now()
	row.MinorVersion = CurrentSecretKeyRowMinorVersion
	prev := s.data.Keys[pos]
	s.data.Keys[pos] = row

	s.dirty = true

	recover := func() {
		s.data.Keys[pos] = prev
		s.dirty = false
	}

	return recover, nil
}

func (s *SecretStore) UpdateAndSave(
	ctx context.Context,
	row lcl.LabeledSecretKeyBundle,
) error {
	s.Lock()
	defer s.Unlock()
	recover, err := s.updateWithLock(row)
	if err != nil {
		return err
	}
	err = s.saveWithLock(ctx)
	if err != nil {
		if recover != nil {
			recover()
		}
		return err
	}
	return nil
}
