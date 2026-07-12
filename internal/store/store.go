// Package store defines MnemoCA's persistence boundary (ADR-0010): a narrow
// document-store interface with exactly two implementations — embedded bbolt
// (default, single node) and MongoDB via goodm (HA). Buckets are namespaced
// by path segments (e.g. "tenants", "certs/<tenant>") so every consumer
// stays tenant-scoped by construction (ADR-0006).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("store: not found")

// Store is the persistence interface. Values are opaque bytes (JSON in
// practice; use the generic helpers below). Implementations must make
// Update and Take atomic with respect to concurrent writers.
type Store interface {
	// Put stores data under path/key, overwriting any existing value.
	Put(ctx context.Context, path []string, key string, data []byte) error
	// Get returns the value at path/key, or ErrNotFound.
	Get(ctx context.Context, path []string, key string) ([]byte, error)
	// Take atomically returns and deletes the value at path/key, or
	// ErrNotFound (single-use tokens: ACME nonces).
	Take(ctx context.Context, path []string, key string) ([]byte, error)
	// Delete removes path/key; missing keys are not an error.
	Delete(ctx context.Context, path []string, key string) error
	// ForEach iterates all documents under path in key order.
	ForEach(ctx context.Context, path []string, fn func(key string, data []byte) error) error
	// Update atomically read-modify-writes path/key. fn receives the current
	// value (nil if absent and createIfMissing) and returns the replacement.
	// Without createIfMissing, absent keys return ErrNotFound.
	Update(ctx context.Context, path []string, key string, createIfMissing bool, fn func(data []byte) ([]byte, error)) error
	// NextSeq returns a monotonically increasing counter for path (serial
	// state: CRL numbers, audit sequence bootstrap).
	NextSeq(ctx context.Context, path []string) (uint64, error)
	// Close releases the backend.
	Close() error
}

// PutJSON stores v as JSON under path/key.
func PutJSON(ctx context.Context, s Store, path []string, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Put(ctx, path, key, data)
}

// GetJSON loads the JSON document at path/key into v.
func GetJSON(ctx context.Context, s Store, path []string, key string, v any) error {
	data, err := s.Get(ctx, path, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// TakeJSON atomically loads-and-deletes the JSON document at path/key.
func TakeJSON(ctx context.Context, s Store, path []string, key string, v any) error {
	data, err := s.Take(ctx, path, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ForEachJSON iterates all documents under path, unmarshaling each into T.
func ForEachJSON[T any](ctx context.Context, s Store, path []string, fn func(key string, v T) error) error {
	return s.ForEach(ctx, path, func(key string, data []byte) error {
		var v T
		if err := json.Unmarshal(data, &v); err != nil {
			return fmt.Errorf("store: corrupt document %v/%s: %w", path, key, err)
		}
		return fn(key, v)
	})
}

// UpdateJSON atomically read-modify-writes the JSON document at path/key,
// starting from T's zero value if absent and createIfMissing.
func UpdateJSON[T any](ctx context.Context, s Store, path []string, key string, createIfMissing bool, fn func(v *T) error) error {
	return s.Update(ctx, path, key, createIfMissing, func(data []byte) ([]byte, error) {
		var v T
		if data != nil {
			if err := json.Unmarshal(data, &v); err != nil {
				return nil, err
			}
		}
		if err := fn(&v); err != nil {
			return nil, err
		}
		return json.Marshal(v)
	})
}
