package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/dwoolworth/goodm"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Collection names (ADR-0010: one generic documents collection plus one
// counters collection — deliberately not per-entity collections).
const (
	docsCollection     = "documents"
	countersCollection = "counters"
)

// Doc is the goodm model for one stored document: the joined bucket path
// (e.g. "certs/acme-corp"), the key within it, and the opaque JSON value.
type Doc struct {
	goodm.Model `bson:",inline"`
	Path        string `bson:"path"`
	Key         string `bson:"key"`
	Data        []byte `bson:"data"`
}

// Indexes declares the unique compound index that makes (path, key) the
// primary lookup and prevents duplicate documents under concurrent creates.
func (*Doc) Indexes() []goodm.CompoundIndex {
	return []goodm.CompoundIndex{goodm.NewUniqueCompoundIndex("path", "key")}
}

// Counter is the goodm model backing NextSeq: one atomically $inc'd sequence
// per path.
type Counter struct {
	goodm.Model `bson:",inline"`
	Path        string `bson:"path" goodm:"unique"`
	Seq         int64  `bson:"seq"`
}

// registerModels registers the goodm schemas exactly once per process
// (goodm's registry is global).
var registerModels = sync.OnceValue(func() error {
	if err := goodm.Register(&Doc{}, docsCollection); err != nil {
		return err
	}
	return goodm.Register(&Counter{}, countersCollection)
})

// Mongo is the MongoDB implementation of Store (ADR-0010): the HA backend.
// Atomic read-modify-write uses goodm's optimistic version (__v) with retry;
// atomic take uses findOneAndDelete.
type Mongo struct {
	client *mongo.Client
	db     *mongo.Database
}

var _ Store = (*Mongo)(nil)

// OpenMongo connects to MongoDB at uri, ensures indexes on dbName, and
// returns the store.
func OpenMongo(ctx context.Context, uri, dbName string) (*Mongo, error) {
	if uri == "" {
		return nil, fmt.Errorf("store: mongo URI is empty (set --mongo-uri or $MNEMOCA_MONGO_URI)")
	}
	if dbName == "" {
		dbName = "mnemoca"
	}
	if err := registerModels(); err != nil {
		return nil, fmt.Errorf("store: registering mongo models: %w", err)
	}
	db, err := goodm.Connect(ctx, uri, dbName)
	if err != nil {
		return nil, fmt.Errorf("store: connecting to mongo: %w", err)
	}
	if err := goodm.Enforce(ctx, db); err != nil {
		_ = db.Client().Disconnect(ctx)
		return nil, fmt.Errorf("store: enforcing mongo indexes: %w", err)
	}
	return &Mongo{client: db.Client(), db: db}, nil
}

// Close disconnects from MongoDB.
func (m *Mongo) Close() error {
	return m.client.Disconnect(context.Background())
}

// joinPath validates and joins bucket path segments into the stored path
// string (segments never contain "/": tenant IDs, "acme", object kinds).
func joinPath(path []string) (string, error) {
	if len(path) == 0 {
		return "", fmt.Errorf("store: empty bucket path")
	}
	return strings.Join(path, "/"), nil
}

func docFilter(p, key string) bson.M { return bson.M{"path": p, "key": key} }

func (m *Mongo) Put(ctx context.Context, path []string, key string, data []byte) error {
	// Route through Update so creation races resolve via the unique index +
	// retry instead of a second code path.
	return m.Update(ctx, path, key, true, func([]byte) ([]byte, error) {
		return data, nil
	})
}

func (m *Mongo) Get(ctx context.Context, path []string, key string) ([]byte, error) {
	p, err := joinPath(path)
	if err != nil {
		return nil, err
	}
	var doc Doc
	if err := goodm.FindOne(ctx, docFilter(p, key), &doc, goodm.FindOptions{DB: m.db}); err != nil {
		if errors.Is(err, goodm.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: mongo get %s/%s: %w", p, key, err)
	}
	return doc.Data, nil
}

func (m *Mongo) Take(ctx context.Context, path []string, key string) ([]byte, error) {
	p, err := joinPath(path)
	if err != nil {
		return nil, err
	}
	// findOneAndDelete is the atomic single-winner primitive the interface
	// requires; goodm has no wrapper for it, so use the driver directly.
	var doc Doc
	err = m.db.Collection(docsCollection).FindOneAndDelete(ctx, docFilter(p, key)).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: mongo take %s/%s: %w", p, key, err)
	}
	return doc.Data, nil
}

func (m *Mongo) Delete(ctx context.Context, path []string, key string) error {
	p, err := joinPath(path)
	if err != nil {
		return err
	}
	err = goodm.DeleteOne(ctx, docFilter(p, key), &Doc{}, goodm.DeleteOptions{DB: m.db})
	if err != nil && !errors.Is(err, goodm.ErrNotFound) {
		return fmt.Errorf("store: mongo delete %s/%s: %w", p, key, err)
	}
	return nil
}

func (m *Mongo) ForEach(ctx context.Context, path []string, fn func(key string, data []byte) error) error {
	p, err := joinPath(path)
	if err != nil {
		return err
	}
	cursor, err := goodm.FindCursor(ctx, bson.M{"path": p}, &Doc{}, goodm.FindOptions{
		DB:   m.db,
		Sort: bson.D{{Key: "key", Value: 1}},
	})
	if err != nil {
		return fmt.Errorf("store: mongo scan %s: %w", p, err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	for cursor.Next(ctx) {
		var doc Doc
		if err := cursor.Decode(&doc); err != nil {
			return fmt.Errorf("store: mongo scan %s: decoding: %w", p, err)
		}
		if err := fn(doc.Key, doc.Data); err != nil {
			return err
		}
	}
	if err := cursor.Err(); err != nil {
		return fmt.Errorf("store: mongo scan %s: %w", p, err)
	}
	return nil
}

// updateMaxAttempts bounds the optimistic-concurrency retry loop; each retry
// implies another writer made progress, so the loop is effectively
// starvation-bounded by the number of concurrent writers.
const updateMaxAttempts = 128

func (m *Mongo) Update(ctx context.Context, path []string, key string, createIfMissing bool, fn func(data []byte) ([]byte, error)) error {
	p, err := joinPath(path)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < updateMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var doc Doc
		err := goodm.FindOne(ctx, docFilter(p, key), &doc, goodm.FindOptions{DB: m.db})
		switch {
		case errors.Is(err, goodm.ErrNotFound):
			if !createIfMissing {
				return ErrNotFound
			}
			out, err := fn(nil)
			if err != nil {
				return err
			}
			create := &Doc{Path: p, Key: key, Data: out}
			err = goodm.Create(ctx, create, goodm.CreateOptions{DB: m.db})
			if mongo.IsDuplicateKeyError(err) {
				continue // lost the creation race; re-read and modify
			}
			if err != nil {
				return fmt.Errorf("store: mongo update %s/%s: %w", p, key, err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("store: mongo update %s/%s: %w", p, key, err)
		}
		out, err := fn(doc.Data)
		if err != nil {
			return err
		}
		doc.Data = out
		err = goodm.Update(ctx, &doc, goodm.UpdateOptions{DB: m.db})
		if errors.Is(err, goodm.ErrVersionConflict) || errors.Is(err, goodm.ErrNotFound) {
			continue // another writer replaced or deleted it; retry from a fresh read
		}
		if err != nil {
			return fmt.Errorf("store: mongo update %s/%s: %w", p, key, err)
		}
		return nil
	}
	return fmt.Errorf("store: mongo update %s/%s: gave up after %d conflicts", p, key, updateMaxAttempts)
}

func (m *Mongo) NextSeq(ctx context.Context, path []string) (uint64, error) {
	p, err := joinPath(path)
	if err != nil {
		return 0, err
	}
	// Atomic $inc with upsert; the unique index on path makes a concurrent
	// first-upsert race surface as a duplicate-key error, which we retry.
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	for attempt := 0; attempt < updateMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var c Counter
		err := m.db.Collection(countersCollection).FindOneAndUpdate(ctx,
			bson.M{"path": p}, bson.M{"$inc": bson.M{"seq": 1}}, opts).Decode(&c)
		if mongo.IsDuplicateKeyError(err) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("store: mongo next-seq %s: %w", p, err)
		}
		return uint64(c.Seq), nil
	}
	return 0, fmt.Errorf("store: mongo next-seq %s: gave up after %d conflicts", p, updateMaxAttempts)
}
