package output

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A bytes.Buffer is not an *os.File, so NewSpinner must treat it as
// non-interactive and disable itself — no animation bytes should ever reach a
// piped/redirected stream.
func TestSpinnerDisabledForNonInteractive(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(Options{ErrOut: &buf, NoColor: true}, "working…")
	if s.enabled() {
		t.Fatalf("spinner should be disabled for a non-tty writer")
	}
	s.Start()
	time.Sleep(10 * time.Millisecond)
	s.Stop()
	if buf.Len() != 0 {
		t.Fatalf("disabled spinner wrote %q, want nothing", buf.String())
	}
}

func TestSpinnerDisabledForJSON(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(Options{ErrOut: &buf, NoColor: true, JSON: true}, "working…")
	if s.enabled() {
		t.Fatalf("spinner should be disabled in JSON mode")
	}
}

// Stop without Start (and a nil spinner) must be safe no-ops.
func TestSpinnerStopSafety(t *testing.T) {
	var nilSpinner *Spinner
	nilSpinner.Start()
	nilSpinner.Stop()

	var buf bytes.Buffer
	s := NewSpinner(Options{ErrOut: &buf, NoColor: true}, "x")
	s.Stop() // never started
}

// frameLine is the pure render unit; verify glyph + message without color.
func TestSpinnerFrameLine(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(Options{ErrOut: &buf, NoColor: true}, "loading")
	line := s.frameLine(0)
	if !strings.HasSuffix(line, " loading") {
		t.Fatalf("frame line %q missing message", line)
	}
	if !strings.HasPrefix(line, spinnerFrames[0]) {
		t.Fatalf("frame line %q missing first glyph %q", line, spinnerFrames[0])
	}
	// Frames cycle.
	if s.frameLine(len(spinnerFrames)) != s.frameLine(0) {
		t.Fatalf("frames should wrap around")
	}
}

// When force-enabled with a tiny delay, the spinner animates and then clears
// its line on Stop (trailing carriage-return + blanking).
func TestSpinnerAnimatesAndClears(t *testing.T) {
	var buf bytes.Buffer
	s := &Spinner{out: &buf, c: Options{NoColor: true}.color(), msg: "syncing", delay: 0}
	s.Start()
	time.Sleep(50 * time.Millisecond)
	s.Stop()

	out := buf.String()
	if !strings.Contains(out, "syncing") {
		t.Fatalf("expected animated output to contain message, got %q", out)
	}
	if !strings.Contains(out, "\r") {
		t.Fatalf("expected carriage-return redraws, got %q", out)
	}
	if !strings.HasSuffix(out, "\r") {
		t.Fatalf("expected line to be cleared on stop, got %q", out)
	}
}
