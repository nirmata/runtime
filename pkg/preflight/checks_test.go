package preflight

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEBPFCapabilityCheck(t *testing.T) {
	err := EBPFCapabilityCheck(nil)
	if runtime.GOOS != "linux" {
		require.Error(t, err)
		require.Contains(t, err.Error(), "linux")
		return
	}
	// On linux hosts this check depends on bpf fs availability.
	if err != nil {
		t.Logf("preflight check reported: %v", err)
	}
}

func TestEBPFCapabilityCheck_NonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("test only runs on non-Linux")
	}

	err := EBPFCapabilityCheck(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "linux")
}

func TestEBPFCapabilityCheck_Linux_BPFFSAvailable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test only runs on Linux")
	}

	// Check if bpf filesystem is available
	info, err := os.Stat(bpfFSPath)
	if err != nil || !info.IsDir() {
		t.Skip("bpf filesystem not available on this system")
	}

	err = EBPFCapabilityCheck(nil)
	require.NoError(t, err)
}

func TestEBPFCapabilityCheck_Linux_BPFFSNotAvailable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test only runs on Linux")
	}

	// This test assumes /sys/fs/bpf doesn't exist or isn't a directory
	// It's more of a documentation test for the error case
	// In a real environment, this would fail if bpf fs is available
	info, err := os.Stat(bpfFSPath)
	if err == nil && info.IsDir() {
		// BPF FS exists, can't test the error case
		t.Logf("bpf filesystem is available, skipping negative test")
		return
	}

	err = EBPFCapabilityCheck(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "bpf filesystem")
}
