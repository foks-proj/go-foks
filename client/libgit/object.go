// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

type ObjectStorage struct {
	adptr *adapter
}

// NewEncodedObject returns a new plumbing.EncodedObject, the real type
// of the object can be a custom implementation or the default one,
// plumbing.MemoryObject.
func (o *ObjectStorage) NewEncodedObject() plumbing.EncodedObject {
	return &plumbing.MemoryObject{}
}

// SetEncodedObject saves an object into the storage, the object should
// be create with the NewEncodedObject, method, and file if the type is
// not supported.
func (o *ObjectStorage) SetEncodedObject(obj plumbing.EncodedObject) (plumbing.Hash, error) {
	return o.adptr.pushEncodedObject(context.Background(), obj)
}

// EncodedObject gets an object by hash with the given
// plumbing.ObjectType. Implementors should return
// (nil, plumbing.ErrObjectNotFound) if an object doesn't exist with
// both the given hash and object type.
//
// Valid plumbing.ObjectType values are CommitObject, BlobObject, TagObject,
// TreeObject and AnyObject. If plumbing.AnyObject is given, the object must
// be looked up regardless of its type.
func (o *ObjectStorage) EncodedObject(typ plumbing.ObjectType, hsh plumbing.Hash) (plumbing.EncodedObject, error) {
	return o.adptr.fetchEncodedObject(context.Background(), typ, hsh)
}

// IterObjects returns a custom EncodedObjectStorer over all the object
// on the storage.
//
// Valid plumbing.ObjectType values are CommitObject, BlobObject, TagObject,
func (o *ObjectStorage) IterEncodedObjects(typ plumbing.ObjectType) (storer.EncodedObjectIter, error) {
	return o.adptr.openObjectIter(context.Background(), typ)
}

// HasEncodedObject returns ErrObjNotFound if the object doesn't
// exist.  If the object does exist, it returns nil.
func (o *ObjectStorage) HasEncodedObject(h plumbing.Hash) error {
	_, err := o.adptr.statEncodedObject(context.Background(), h)
	return err
}

// EncodedObjectSize returns the plaintext size of the encoded object.
func (o *ObjectStorage) EncodedObjectSize(h plumbing.Hash) (int64, error) {
	obj, err := o.adptr.fetchEncodedObject(context.Background(), plumbing.AnyObject, h)
	if err != nil {
		return 0, err
	}
	return obj.Size(), nil
}

func (o *ObjectStorage) AddAlternate(remote string) error {
	return core.NotImplementedError{}
}

var _ storer.EncodedObjectStorer = (*ObjectStorage)(nil)
