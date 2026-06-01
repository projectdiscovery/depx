package audit

import (
	"sync"

	scalibrlog "github.com/google/osv-scalibr/log"
)

type noopLogger struct{}

func (noopLogger) Errorf(string, ...any) {}
func (noopLogger) Error(...any)         {}
func (noopLogger) Warnf(string, ...any) {}
func (noopLogger) Warn(...any)          {}
func (noopLogger) Infof(string, ...any) {}
func (noopLogger) Info(...any)          {}
func (noopLogger) Debugf(string, ...any) {}
func (noopLogger) Debug(...any)         {}

var scalibrLogMu sync.Mutex

// beginScalibrExtractSession silences osv-scalibr's internal logger during dependency extraction.
func beginScalibrExtractSession() func() {
	scalibrLogMu.Lock()
	scalibrlog.SetLogger(noopLogger{})
	return func() {
		scalibrlog.SetLogger(&scalibrlog.DefaultLogger{})
		scalibrLogMu.Unlock()
	}
}
