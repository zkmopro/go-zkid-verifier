package verifier

/*
#cgo LDFLAGS: -lzk_verifier -lm
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../lib/aarch64-apple-darwin -Wl,-rpath,${SRCDIR}/../lib/aarch64-apple-darwin -lwitnesscalc_device_sig_rs2048 -lfr -lgmp -lc++
#cgo linux LDFLAGS: -L${SRCDIR}/../lib/x86_64-unknown-linux-gnu -Wl,-rpath,${SRCDIR}/../lib/x86_64-unknown-linux-gnu -lwitnesscalc_device_sig_rs2048 -lfr -lgmp -lstdc++
#include <stdint.h>
#include <stdlib.h>

extern int         zk_link_verify(const char *base_dir, int cert_chain_type);
extern const char *zk_last_error();
extern const char *zk_last_signals();
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime"
	"unsafe"
)

// PublicSignals holds the raw field-element outputs from both ZK circuits,
// serialized as 0x-prefixed little-endian hex strings.
type PublicSignals struct {
	CertChain []string `json:"cert_chain"`
	DeviceSig []string `json:"device_sig"`
}

// CertChainType selects the certificate chain RSA key size variant.
type CertChainType int

const (
	CertChainRS2048 CertChainType = 0 // cert_chain_rs2048 + device_sig_rs2048
	CertChainRS4096 CertChainType = 1 // cert_chain_rs4096 + device_sig_rs2048
)

func lastError() error {
	msg := C.GoString(C.zk_last_error())
	if msg == "" {
		return errors.New("unknown error")
	}
	return errors.New(msg)
}

func lastSignals() *PublicSignals {
	raw := C.GoString(C.zk_last_signals())
	var s PublicSignals
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil
	}
	return &s
}

// LinkVerify verifies cert-chain + device-sig proofs and checks pk_commit linkage.
//
// Reads from {baseDir}/keys/:
//   - cert_chain proof (rs2048 or rs4096 depending on certChainType)
//   - device_sig_rs2048 proof
//   - corresponding verifying keys
//
// Returns (verified, signals, error). signals is non-nil whenever the FFI call
// completed without error, regardless of whether the proofs matched.
func LinkVerify(baseDir string, certChainType CertChainType) (bool, *PublicSignals, error) {
	// Lock to OS thread so zk_last_signals() reads the same thread-local as
	// zk_link_verify() wrote.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cBase := C.CString(baseDir)
	defer C.free(unsafe.Pointer(cBase))

	ret := C.zk_link_verify(cBase, C.int(certChainType))
	switch {
	case ret > 0:
		return true, lastSignals(), nil
	case ret == 0:
		return false, lastSignals(), nil
	default:
		return false, nil, lastError()
	}
}
