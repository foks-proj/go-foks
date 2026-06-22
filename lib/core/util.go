// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
)

func Reverse[T any](s []T) []T {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func Ptr[T any](v T) *T {
	return &v
}

func Last[T any](v []T) T {
	return v[len(v)-1]
}

func LastOrNil[T any](v []T) *T {
	if len(v) == 0 {
		return nil
	}
	return &v[len(v)-1]
}

func Find[T any](v []T, f func(t T) bool) bool {
	for _, t := range v {
		if f(t) {
			return true
		}
	}
	return false
}

func GlobToRegexp(s string) (*regexp.Regexp, error) {

	s = strings.Replace(s, ".", "\\.", -1)
	s = strings.Replace(s, "*", "[0-9A-Za-z_.-]*", -1)

	r, err := regexp.Compile("^" + s + "$")
	if err != nil {
		return nil, err
	}
	return r, nil
}

func Sel[T any](b bool, t T, f T) T {
	if b {
		return t
	}
	return f
}

func LazySel[T any](b bool, t func() T, f func() T) T {
	if b {
		return t()
	}
	return f()
}

func Unique[T comparable](ts []T) []T {
	seen := make(map[T]struct{})
	result := make([]T, 0, len(ts))
	for _, t := range ts {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			result = append(result, t)
		}
	}
	return result
}

func Or[T any](t *T, f *T) *T {
	if t != nil {
		return t
	}
	return f
}

func Include[T any](b bool, t T) *T {
	if b {
		return &t
	}
	return nil
}

func Compose(f func(), g func()) func() {
	if f == nil {
		return g
	}
	if g == nil {
		return f
	}
	return func() {
		f()
		g()
	}
}

// An object used to force a race in test.
type TestStopper struct {
	sync.RWMutex
	waiter chan<- chan struct{}
}

func (r *TestStopper) Init() <-chan chan struct{} {
	r.Lock()
	defer r.Unlock()

	if r.waiter != nil {
		panic("cannot call stopper twice")
	}

	ret := make(chan chan struct{})
	r.waiter = ret
	return ret
}

func (r *TestStopper) Wait() {

	var earlyOut bool
	r.RLock()
	earlyOut = r.waiter == nil
	r.RUnlock()

	if earlyOut {
		return
	}

	var ch chan<- chan struct{}
	r.Lock()
	if r.waiter != nil {
		ch = r.waiter
		r.waiter = nil
	}
	r.Unlock()
	if ch == nil {
		return
	}
	resultCh := make(chan struct{})
	ch <- resultCh
	<-resultCh
}

func Map[T, V any](ts []T, fn func(T) V) []V {
	result := make([]V, len(ts))
	for i, t := range ts {
		result[i] = fn(t)
	}
	return result
}

func Values[K comparable, T any](m map[K]T) []T {
	result := make([]T, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}

func Keys[K comparable, T any](m map[K]T) []K {
	result := make([]K, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}

func NonCryptoRandomSel[T any](ts []T) (T, error) {
	var zed T
	if len(ts) == 0 {
		return zed, NotFoundError("no elements")
	}
	if len(ts) == 1 {
		return ts[0], nil
	}
	val := rand.Int32()
	return ts[val%int32(len(ts))], nil
}
