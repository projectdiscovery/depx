package cli

import (
	"strings"
	"testing"
)

func TestReadStdinLinesRejectsOversizedLine(t *testing.T) {
	_, err := readStdinLines(strings.NewReader(strings.Repeat("a", maxStdinLineBytes+1) + "\n"))
	if err == nil {
		t.Fatal("expected error for oversized stdin line")
	}
	if !strings.Contains(err.Error(), "stdin line exceeds maximum size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadStdinLinesAcceptsLargeLineUnderLimit(t *testing.T) {
	line := strings.Repeat("b", maxStdinLineBytes-1)
	lines, err := readStdinLines(strings.NewReader(line + "\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0] != line {
		t.Fatalf("unexpected lines: %#v", lines)
	}
}
