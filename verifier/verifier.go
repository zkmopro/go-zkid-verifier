package verifier

/*
#cgo LDFLAGS: -lzk_verifier -lwitnesscalc_rs256 -lm
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../lib/aarch64-apple-darwin -Wl,-rpath,${SRCDIR}/../lib/aarch64-apple-darwin -lc++
#cgo linux LDFLAGS: -L${SRCDIR}/../lib/x86_64-unknown-linux-gnu -Wl,-rpath,${SRCDIR}/../lib/x86_64-unknown-linux-gnu -lstdc++
#include <stdint.h>
#include <stdlib.h>

extern int         zk_link_verify(const char *base_dir, int cert_chain_type);
extern const char *zk_last_error();
*/
import "C"
import (
	"errors"
	"unsafe"
)

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

// LinkVerify verifies cert-chain + device-sig proofs and checks pk_commit linkage.
//
// Reads from {baseDir}/keys/:
//   - cert_chain proof (rs2048 or rs4096 depending on certChainType)
//   - device_sig_rs2048 proof
//   - corresponding verifying keys
//
// Returns true if both proofs are valid and pk_commit values match.
func LinkVerify(baseDir string, certChainType CertChainType) (bool, error) {
	cBase := C.CString(baseDir)
	defer C.free(unsafe.Pointer(cBase))

	ret := C.zk_link_verify(cBase, C.int(certChainType))
	switch {
	case ret > 0:
		return true, nil
	case ret == 0:
		return false, nil
	default:
		return false, lastError()
	}
}
