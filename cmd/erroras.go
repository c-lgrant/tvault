package cmd

import "errors"

func asCLIErr(err error, target any) bool { return errors.As(err, target) }
