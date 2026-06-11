package utils

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
