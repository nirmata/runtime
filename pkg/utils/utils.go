package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// return the entries in array b and not a
func DiffSlice[T comparable](a, b []T) []T {
	set := make(map[T]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	var out []T
	for _, v := range b {
		if _, ok := set[v]; !ok {
			out = append(out, v)
		}
	}
	return out
}

// BpfLSMEnabled reports whether "bpf" is in the kernel's active LSM list. A
// non-nil error means the list could not be read at all, which callers must not
// treat as "disabled": the usual cause is securityfs being unmounted in the
// current mount namespace, and the kernel underneath may well have BPF-LSM on.
func BpfLSMEnabled() (bool, error) {
	const lsmList = "/sys/kernel/security/lsm"
	data, err := os.ReadFile(lsmList)
	if errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("%s is absent; securityfs is probably not mounted here: %w", lsmList, err)
	}
	if err != nil {
		return false, err
	}
	if slices.Contains(strings.Split(strings.TrimSpace(string(data)), ","), "bpf") {
		return true, nil
	}
	return false, nil
}

func MergeMapCount[T comparable](dst map[T]uint32, src map[T]uint32) {
	for k, v := range src {
		dst[k] += v
	}
}
