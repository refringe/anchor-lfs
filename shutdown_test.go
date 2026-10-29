package main

import (
	"context"
	"errors"
	"testing"
)

func TestAwaitStopRestoresSignals(t *testing.T) {
	tests := []struct {
		name     string
		signal   bool
		serveErr error
		wantCode int
	}{
		{name: "signal", signal: true, wantCode: 0},
		{name: "serve failure", serveErr: errors.New("accept failed"), wantCode: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signalled, sendSignal := context.WithCancel(t.Context())
			defer sendSignal()
			if tt.signal {
				sendSignal()
			}
			served := make(chan error, 1)
			if tt.serveErr != nil {
				served <- tt.serveErr
			}

			restored := false
			code := awaitStop(signalled, func() { restored = true }, served, "30s")
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !restored {
				t.Error("default signal handling was not restored")
			}
		})
	}
}
