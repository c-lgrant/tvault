//go:build !unix

package config

import "errors"

// LockIDTokenCache has no cross-process lock on this platform. Callers
// refresh without it: the cache still works, a burst may just refresh more
// than once.
func LockIDTokenCache() (unlock func(), err error) {
	return nil, errors.New("no cross-process lock on this platform")
}
