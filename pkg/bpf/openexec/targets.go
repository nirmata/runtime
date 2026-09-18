package openexec

import (
	"unsafe"

	"github.com/nirmata/runtime/pkg/compiler"
)

// PathKeys turns the accepted values of one allow or deny list into policy map
// entries: each path's bytes NUL-padded to the width the kernel side declares,
// exactly as bpf_probe_read_kernel_str leaves it. A directory prefix keys the
// same width under its own discriminant, keeping the trailing separator the
// kernel's ancestor walk produces. compiler.StarTarget yields no entry; it sets
// star, the default-deny sentinel SetDefaultDeny carries.
func PathKeys(values []string, allow bool) (keys []*runtimePolicyEntry, star bool, rejected []compiler.RejectedTarget) {
	paths, prefixes, star, rejected := compiler.ParsePathList(values)

	pathType, prefixType := dataTypeDeny, dataTypeDenyPrefix
	if allow {
		pathType, prefixType = dataTypeAllow, dataTypeAllowPrefix
	}

	for _, p := range paths {
		keys = append(keys, pathEntry(pathType, p))
	}
	for _, p := range prefixes {
		keys = append(keys, pathEntry(prefixType, p))
	}
	return keys, star, rejected
}

func pathEntry(dataType uint32, path string) *runtimePolicyEntry {
	entry := &runtimePolicyEntry{DataType: dataType}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&entry.Data[0])), len(entry.Data)), path)
	return entry
}
