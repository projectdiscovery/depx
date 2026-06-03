package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
)

// spinnerFrames is a braille dot cycle — compact, glyph-stable across terminals,
// and the de-facto standard for CLI activity indicators.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	// spinnerStartDelay holds the spinner back briefly so fast operations
	// (warm cache, instant API hits) never flash an indicator.
	spinnerStartDelay = 120 * time.Millisecond
	spinnerInterval   = 90 * time.Millisecond
)

// Spinner is an indeterminate activity indicator for blocking work (network or
// API calls) that has no granular progress to report. It animates on stderr
// only for interactive terminals, so it never pollutes piped output, JSON, or
// CI logs. A nil or disabled Spinner is safe to Start/Stop.
type Spinner struct {
	out   io.Writer
	c     aurora.Aurora
	msg   string
	delay time.Duration

	mu      sync.Mutex
	stop    chan struct{}
	done    chan struct{}
	started bool
	lastLen int
}

// NewSpinner returns a spinner bound to o.ErrOut. It is automatically disabled
// (turned into a no-op) for JSON output and non-interactive writers, so callers
// can wrap any blocking call unconditionally.
func NewSpinner(o Options, msg string) *Spinner {
	errOut := o.ErrOut
	if errOut == nil {
		errOut = os.Stderr
	}
	s := &Spinner{
		out:   errOut,
		c:     o.color(),
		msg:   msg,
		delay: spinnerStartDelay,
	}
	if o.JSON || !isInteractive(errOut) {
		s.out = nil
	}
	return s
}

func (s *Spinner) enabled() bool {
	return s != nil && s.out != nil
}

// Start begins animating after the start delay. Safe to call once; subsequent
// calls are ignored until Stop.
func (s *Spinner) Start() {
	if !s.enabled() {
		return
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	s.mu.Unlock()

	go s.loop()
}

// Stop halts the animation and clears the spinner line. Safe to call multiple
// times and on a spinner that never started.
func (s *Spinner) Stop() {
	if !s.enabled() {
		return
	}
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	stop, done := s.stop, s.done
	s.mu.Unlock()

	close(stop)
	<-done

	s.mu.Lock()
	if s.lastLen > 0 {
		fmt.Fprintf(s.out, "\r%s\r", strings.Repeat(" ", s.lastLen))
		s.lastLen = 0
	}
	s.started = false
	s.mu.Unlock()
}

func (s *Spinner) loop() {
	defer close(s.done)

	select {
	case <-s.stop:
		return
	case <-time.After(s.delay):
	}

	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()

	frame := 0
	s.render(frame)
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			frame++
			s.render(frame)
		}
	}
}

func (s *Spinner) render(frame int) {
	line := s.frameLine(frame)
	s.mu.Lock()
	defer s.mu.Unlock()
	pad := ""
	if len(line) < s.lastLen {
		pad = strings.Repeat(" ", s.lastLen-len(line))
	}
	fmt.Fprintf(s.out, "\r%s%s", line, pad)
	s.lastLen = len(line)
}

func (s *Spinner) frameLine(frame int) string {
	glyph := spinnerFrames[frame%len(spinnerFrames)]
	s.mu.Lock()
	msg := s.msg
	s.mu.Unlock()
	return fmt.Sprintf("%s %s", s.c.Cyan(glyph).String(), msg)
}

// SetMessage updates the spinner label while it is running.
func (s *Spinner) SetMessage(msg string) {
	if s == nil || msg == "" {
		return
	}
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

func isInteractive(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
