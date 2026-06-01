package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/projectdiscovery/depx/internal/apperr"
)

const maxStdinLineBytes = 256 * 1024

func stdinIsPipe() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice == 0
}

func readStdinLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxStdinLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return nil, apperr.Usage(fmt.Sprintf("stdin line exceeds maximum size (%dKB)", maxStdinLineBytes/1024))
		}
		return nil, err
	}
	return lines, nil
}

func resolveCheckRefs(args []string) ([]string, error) {
	refs := append([]string(nil), args...)
	if stdinIsPipe() {
		lines, err := readStdinLines(os.Stdin)
		if err != nil {
			return nil, apperr.Usage(err.Error())
		}
		refs = append(refs, lines...)
	}
	if len(refs) == 0 {
		return nil, apperr.Usage("package reference is required (argument or stdin)")
	}
	return refs, nil
}
