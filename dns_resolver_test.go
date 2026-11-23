package main

import (
	"errors"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		value     string
		allowZero bool
		want      time.Duration
		// wantErr is the error expected; fails marks a failure of any kind.
		wantErr error
		fails   bool
	}{
		{name: "positive", value: "4s", want: 4 * time.Second},
		{name: "zero allowed", value: "0", allowZero: true, want: 0},
		{name: "zero refused", value: "0s", wantErr: errNonPositiveDuration},
		{name: "negative", value: "-1s", allowZero: true, wantErr: errNegativeDuration},
		{name: "malformed", value: "soon", allowZero: true, fails: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDuration(testCase.value, testCase.allowZero)
			if testCase.fails {
				if err == nil {
					t.Fatalf("parseDuration(%q) succeeded; want an error", testCase.value)
				}
				return
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("parseDuration(%q) error = %v; want %v", testCase.value, err, testCase.wantErr)
			}
			if got != testCase.want {
				t.Fatalf("parseDuration(%q) = %s; want %s", testCase.value, got, testCase.want)
			}
		})
	}
}
