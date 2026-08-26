package openexec

import (
	"github.com/nirmata/runtime/pkg/compiler"
)

// PathKeys returns the banned/allowed map keys for one behavior's path values:
// each path's bytes NUL-padded to the width the kernel side declares, exactly
// as bpf_probe_read_kernel_str leaves it. compiler.StarTarget yields no key; it
// sets star, the default-deny sentinel SetDefaultDeny carries.
func PathKeys(values []string) (keys [][maxPathLen]byte, star bool, rejected []compiler.RejectedTarget) {
	paths, star, rejected := compiler.ParsePathList(values)
	for _, p := range paths {
		key := [maxPathLen]byte{}
		copy(key[:], p)
		keys = append(keys, key)
	}
	return keys, star, rejected
}
