package errors

import (
	"errors"
)

var (
	ErrNoQuestions = errors.New("no questions")
	// TODO: Move?
	ErrNilRemoteAddress = errors.New("nil remote address")
	ErrNilDotConfig = errors.New("nil dot config")
	ErrEmptyMode = errors.New("empty mode")
	ErrUnsupportedMode = errors.New("unsupported mode")
)
