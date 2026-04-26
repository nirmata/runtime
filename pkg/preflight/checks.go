package preflight

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
)

const bpfFSPath = "/sys/fs/bpf"

// EBPFCapabilityCheck verifies minimal host prerequisites for runtime tracing.
func EBPFCapabilityCheck(_ *http.Request) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("runtime tracing requires linux nodes")
	}
	info, err := os.Stat(bpfFSPath)
	if err != nil {
		return fmt.Errorf("bpf filesystem not available at %s: %w", bpfFSPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("bpf filesystem path is not a directory: %s", bpfFSPath)
	}
	return nil
}
