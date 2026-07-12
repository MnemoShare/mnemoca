// Package storetest provides MongoDB fixtures for MnemoCA's tests: it
// prefers $MNEMOCA_TEST_MONGO_URI (CI service container), falls back to
// starting a disposable local Docker container, and skips the test when
// neither is available.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	containerName = "mnemoca-test-mongo"
	containerPort = "27117"
)

var (
	uriOnce sync.Once
	uriVal  string
	uriErr  error
)

// URI returns a MongoDB URI for tests, or skips the test when no MongoDB is
// reachable. The Docker container it may start is left running (--rm cleans
// it up when it is eventually stopped).
func URI(t *testing.T) string {
	t.Helper()
	uriOnce.Do(func() { uriVal, uriErr = resolveURI() })
	if uriErr != nil {
		t.Skipf("mongo unavailable: %v", uriErr)
	}
	return uriVal
}

func resolveURI() (string, error) {
	if v := os.Getenv("MNEMOCA_TEST_MONGO_URI"); v != "" {
		return v, nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("docker not installed and $MNEMOCA_TEST_MONGO_URI unset")
	}
	uri := "mongodb://localhost:" + containerPort
	// Already running (a previous test run left it up)?
	if ping(uri) == nil {
		return uri, nil
	}
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName, "-p", containerPort+":27017", "mongo:8").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "is already in use") {
		return "", fmt.Errorf("starting %s: %v: %s", containerName, err, out)
	}
	// Wait for mongod to accept connections.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := ping(uri); err == nil {
			return uri, nil
		} else if time.Now().After(deadline) {
			return "", fmt.Errorf("mongo container did not become ready: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func ping(uri string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(2 * time.Second))
	if err != nil {
		return err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	return client.Ping(ctx, nil)
}

// TempDB returns the test MongoDB URI plus a fresh random database name that
// is dropped at test cleanup (skips when MongoDB is unavailable).
func TempDB(t *testing.T) (uri, dbName string) {
	t.Helper()
	uri = URI(t)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	dbName = "mnemoca_test_" + hex.EncodeToString(b[:])
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, err := mongo.Connect(options.Client().ApplyURI(uri))
		if err != nil {
			t.Logf("storetest: connecting for cleanup: %v", err)
			return
		}
		defer func() { _ = client.Disconnect(context.Background()) }()
		if err := client.Database(dbName).Drop(ctx); err != nil {
			t.Logf("storetest: dropping %s: %v", dbName, err)
		}
	})
	return uri, dbName
}
