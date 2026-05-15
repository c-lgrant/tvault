package api

import "errors"

func errorsAsImpl(err error, target any) bool { return errors.As(err, target) }
