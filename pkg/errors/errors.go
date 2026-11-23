package errors

import (
	"errors"
)

var (
	ErrNoQuestions     = errors.New("no questions")
	ErrUnsupportedMode = errors.New("unsupported mode")
	ErrClosedPool      = errors.New("closed connection pool")
	ErrNoAnswer        = errors.New("no answer from the upstream")
	ErrAnswerMismatch  = errors.New("answer does not match the question")
)
