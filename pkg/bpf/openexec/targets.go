package openexec

import (
	"unsafe"

	"github.com/nirmata/runtime/pkg/compiler"
)

// PathKeys returns the banned/allowed map keys for one behavior's path values:
// each path's bytes NUL-padded to the width the kernel side declares, exactly
// as bpf_probe_read_kernel_str leaves it. compiler.StarTarget yields no key; it
// sets star, the default-deny sentinel SetDefaultDeny carries.
func PathKeys(values []string, allow bool) (keys []*runtimePolicyEntry, star bool, rejected []compiler.RejectedTarget) {
	paths, star, rejected := compiler.ParsePathList(values)
	for _, p := range paths {
		dataType := 0
		if !allow {
			dataType = 1
		}

		entry := &runtimePolicyEntry{
			DataType: uint32(dataType),
			Data:     [128]int8{},
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&entry.Data[0])), len(entry.Data)), p)

		keys = append(keys, entry)
	}
	return keys, star, rejected
}
