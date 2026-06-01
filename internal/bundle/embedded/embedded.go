//go:build !bootstrap

package embedded

import _ "embed"

//go:embed osv.tar.gz
var OSV []byte

//go:embed pd.tar.gz
var PD []byte
