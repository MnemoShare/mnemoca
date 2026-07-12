// Package store provides MnemoCA's persistence layer: an embedded bbolt
// key-value store with JSON document helpers. Buckets are namespaced by
// path segments (e.g. "tenants", "certs/<tenant>") so every consumer —
// CA engine, ACME server, audit chain head — stays tenant-scoped by
// construction (ADR-0006).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("store: not found")

// Store is a bbolt-backed document store.
type Store struct {
	db *bolt.DB
}

// Open opens (creating if needed) the database file at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func bucketPath(tx *bolt.Tx, segments []string, create bool) (*bolt.Bucket, error) {
	if len(segments) == 0 {
		return nil, fmt.Errorf("store: empty bucket path")
	}
	var b *bolt.Bucket
	for i, seg := range segments {
		if i == 0 {
			if create {
				var err error
				b, err = tx.CreateBucketIfNotExists([]byte(seg))
				if err != nil {
					return nil, err
				}
			} else {
				b = tx.Bucket([]byte(seg))
			}
		} else {
			if create {
				var err error
				b, err = b.CreateBucketIfNotExists([]byte(seg))
				if err != nil {
					return nil, err
				}
			} else {
				b = b.Bucket([]byte(seg))
			}
		}
		if b == nil {
			return nil, ErrNotFound
		}
	}
	return b, nil
}

// PutJSON stores v as JSON under key in the bucket path.
func (s *Store) PutJSON(path []string, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, true)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	})
}

// GetJSON loads the JSON document at key into v.
func (s *Store) GetJSON(path []string, key string, v any) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, false)
		if err != nil {
			return err
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}
		return json.Unmarshal(data, v)
	})
}

// Delete removes key from the bucket path. Missing keys are not an error.
func (s *Store) Delete(path []string, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, false)
		if errors.Is(err, ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		return b.Delete([]byte(key))
	})
}

// ForEachJSON iterates all documents in the bucket path, unmarshaling each
// into a fresh value produced by newV and passing it to fn.
func ForEachJSON[T any](s *Store, path []string, fn func(key string, v T) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, false)
		if errors.Is(err, ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		return b.ForEach(func(k, data []byte) error {
			if data == nil {
				return nil // nested bucket
			}
			var v T
			if err := json.Unmarshal(data, &v); err != nil {
				return fmt.Errorf("store: corrupt document %s/%s: %w", path, k, err)
			}
			return fn(string(k), v)
		})
	})
}

// Update runs fn inside a read-modify-write transaction on a single JSON
// document, creating it from zero value if absent when createIfMissing.
func UpdateJSON[T any](s *Store, path []string, key string, createIfMissing bool, fn func(v *T) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, true)
		if err != nil {
			return err
		}
		var v T
		data := b.Get([]byte(key))
		if data == nil && !createIfMissing {
			return ErrNotFound
		}
		if data != nil {
			if err := json.Unmarshal(data, &v); err != nil {
				return err
			}
		}
		if err := fn(&v); err != nil {
			return err
		}
		out, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), out)
	})
}

// NextSeq returns a monotonically increasing sequence number for the bucket
// path (used for serials and audit sequence numbers).
func (s *Store) NextSeq(path []string) (uint64, error) {
	var seq uint64
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, true)
		if err != nil {
			return err
		}
		seq, err = b.NextSequence()
		return err
	})
	return seq, err
}
