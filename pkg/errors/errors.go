package errors

import (
	"errors"
)

var (
	ErrNoQuestions = errors.New("no questions")
	// TODO: Move?
	ErrNilRemoteAddress = errors.New("nil remote address")
)
