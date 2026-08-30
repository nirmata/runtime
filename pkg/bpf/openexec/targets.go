package openexec

import (
	"unsafe"

	"github.com/nirmata/runtime/pkg/compiler"
)

// PathKeys turns the accepted values of one allow or deny list into policy map
// entries: each path's bytes NUL-padded to the width the kernel side declares,
// exactly as bpf_probe_read_kernel_str leaves it. compiler.StarTarget yields no
// entry; it sets star, the default-deny sentinel SetDefaultDeny carries.
func PathKeys(values []string, allow bool) (keys []*runtimePolicyEntry, star bool, rejected []compiler.RejectedTarget) {
	paths, star, rejected := compiler.ParsePathList(values)
	for _, p := range paths {
		dataType := dataTypeDeny
		if allow {
			dataType = dataTypeAllow
		}

		entry := &runtimePolicyEntry{DataType: dataType}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&entry.Data[0])), len(entry.Data)), p)

		keys = append(keys, entry)
	}
	return keys, star, rejected
}
