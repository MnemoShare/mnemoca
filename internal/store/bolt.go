package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bolt is the embedded bbolt implementation of Store: zero-dependency,
// single-file, single-writer (one pod). The default backend.
type Bolt struct {
	db *bolt.DB
}

var _ Store = (*Bolt)(nil)

// Open opens (creating if needed) the database file at path.
func Open(path string) (*Bolt, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	return &Bolt{db: db}, nil
}

// Close closes the database.
func (s *Bolt) Close() error { return s.db.Close() }

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

func (s *Bolt) Put(_ context.Context, path []string, key string, data []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, true)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	})
}

func (s *Bolt) Get(_ context.Context, path []string, key string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, false)
		if err != nil {
			return err
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), data...)
		return nil
	})
	return out, err
}

func (s *Bolt) Take(_ context.Context, path []string, key string) ([]byte, error) {
	var out []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, false)
		if err != nil {
			return err
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), data...)
		return b.Delete([]byte(key))
	})
	return out, err
}

func (s *Bolt) Delete(_ context.Context, path []string, key string) error {
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

func (s *Bolt) ForEach(_ context.Context, path []string, fn func(key string, data []byte) error) error {
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
			return fn(string(k), data)
		})
	})
}

func (s *Bolt) Update(_ context.Context, path []string, key string, createIfMissing bool, fn func(data []byte) ([]byte, error)) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := bucketPath(tx, path, true)
		if err != nil {
			return err
		}
		data := b.Get([]byte(key))
		if data == nil && !createIfMissing {
			return ErrNotFound
		}
		out, err := fn(data)
		if err != nil {
			return err
		}
		return b.Put([]byte(key), out)
	})
}

func (s *Bolt) NextSeq(_ context.Context, path []string) (uint64, error) {
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
