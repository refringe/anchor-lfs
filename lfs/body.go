package lfs

import (
	"errors"
	"io"
)

// readErrorRecorder passes reads through to reader and keeps the first error other than io.EOF.
type readErrorRecorder struct {
	reader io.Reader
	err    error
}

// Read reads from reader, recording its error unless it is io.EOF or an error is already recorded.
func (r *readErrorRecorder) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && r.err == nil && !errors.Is(err, io.EOF) {
		r.err = err
	}
	return n, err
}
