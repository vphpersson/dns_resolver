package errors

import (
	"errors"
)

var (
	ErrNoQuestions     = errors.New("no questions")
	ErrUnsupportedMode = errors.New("unsupported mode")
	ErrClosedPool      = errors.New("closed connection pool")
)
