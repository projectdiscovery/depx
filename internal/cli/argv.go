package cli

// normalizePDStyleArgs rewrites single-dash long flags used by other PD CLIs
// (goflags) into forms Cobra/pflag understands. Without this, "-version" is
// parsed as bundled short flags (-v -e rsion …) instead of --version.
func normalizePDStyleArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "-version":
			out = append(out, "--version")
		case "-update":
			out = append(out, "--update")
		default:
			out = append(out, arg)
		}
	}
	return out
}
