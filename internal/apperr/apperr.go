package apperr

import "errors"

const (
	CodeSuccess  = 0
	CodeFindings = 1
	CodeUsage    = 2
	CodeUpstream = 3
)

var (
	ErrUsage     = errors.New("usage error")
	ErrUpstream  = errors.New("upstream error")
	ErrFindings  = errors.New("findings")
	ErrNotFound  = errors.New("not found")
	ErrNotConfig = errors.New("not configured")
)

type CodedError struct {
	Code    int
	Message string
	Err     error
}

func (e *CodedError) Error() string {
	if e.Message != "" && e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "error"
}

func (e *CodedError) Unwrap() error { return e.Err }

func Usage(msg string) error {
	return &CodedError{Code: CodeUsage, Message: msg, Err: ErrUsage}
}

func Upstream(msg string, err error) error {
	return &CodedError{Code: CodeUpstream, Message: msg, Err: err}
}

func Findings(msg string) error {
	return &CodedError{Code: CodeFindings, Message: msg, Err: ErrFindings}
}

func ExitCode(err error) int {
	if err == nil {
		return CodeSuccess
	}
	var coded *CodedError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return CodeUsage
}
