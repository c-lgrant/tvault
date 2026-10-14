//go:build unix

package config

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

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
