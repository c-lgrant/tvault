package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// The ID-token cache lets separate tvault processes share one admin ID token
// instead of each one calling POST /api/cli/auth/refresh. Without it every
// `tvault get` refreshes, and a burst of helpers trips the rate limit.
//
// idtokens.json (mode 0600) maps a hash of api_url + refresh token to the
// token and its expiry. Keying on the refresh token means a new login starts
// a new entry, and an entry never outlives its context's refresh token in
// usefulness. A 1-hour ID token is weaker than the refresh token that
// contexts.yaml already holds, so the file adds no new class of secret.
const (
	idTokenCacheFile = "idtokens.json"
	idTokenLockFile  = "idtokens.lock"
	idTokenLockWait  = 30 * time.Second
)

type cachedIDToken struct {
	IDToken   string `json:"id_token"`
	ExpiresAt int64  `json:"expires_at"`
}

func idTokenKey(ctx *Context) string {
	sum := sha256.Sum256([]byte(ctx.APIURL + "\n" + ctx.RefreshToken))
	return hex.EncodeToString(sum[:16])
}

func readIDTokenCache(d string) map[string]cachedIDToken {
	entries := map[string]cachedIDToken{}
	data, err := os.ReadFile(filepath.Join(d, idTokenCacheFile))
	if err != nil {
		return entries
	}
	// A corrupt file is treated as empty; the next store rewrites it.
	_ = json.Unmarshal(data, &entries)
	return entries
}

// CachedIDToken returns the cached ID token for an admin context and its
// expiry (unix seconds), or "" and 0 when there is none.
func CachedIDToken(ctx *Context) (string, int64) {
	d, err := dir()
	if err != nil {
		return "", 0
	}
	e := readIDTokenCache(d)[idTokenKey(ctx)]
	return e.IDToken, e.ExpiresAt
}

// StoreIDToken saves an admin context's ID token for other processes and
// drops entries that have already expired. The caller should hold
// LockIDTokenCache, so concurrent stores do not drop each other's entries.
func StoreIDToken(ctx *Context, token string, expiresAt int64) error {
	return updateIDTokenCache(func(entries map[string]cachedIDToken) {
		entries[idTokenKey(ctx)] = cachedIDToken{IDToken: token, ExpiresAt: expiresAt}
	})
}

// ForgetIDToken removes an admin context's cached ID token. Call it when the
// context is logged out or deleted, so no usable token stays on disk.
func ForgetIDToken(ctx *Context) error {
	if unlock, err := LockIDTokenCache(); err == nil {
		defer unlock()
	}
	return updateIDTokenCache(func(entries map[string]cachedIDToken) {
		delete(entries, idTokenKey(ctx))
	})
}

func updateIDTokenCache(mutate func(map[string]cachedIDToken)) error {
	d, err := dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	entries := readIDTokenCache(d)
	mutate(entries)
	now := time.Now().Unix()
	for k, e := range entries {
		if e.ExpiresAt <= now {
			delete(entries, k)
		}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return writeFileAtomic(d, idTokenCacheFile, data)
}

// LockIDTokenCache takes an exclusive lock that serialises refreshes across
// processes, so a burst of tvault calls makes one refresh, not one each.
// It waits at most idTokenLockWait, then returns an error; callers should
// refresh without the lock rather than fail. The OS releases the lock if the
// process dies, so a crashed holder cannot wedge later calls.
func LockIDTokenCache() (unlock func(), err error) {
	d, err := dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(d, idTokenLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(idTokenLockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			f.Close()
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}
