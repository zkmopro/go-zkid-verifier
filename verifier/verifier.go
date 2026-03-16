package verifier

/*
#cgo LDFLAGS: -L${SRCDIR}/../lib -lzk_verifier -lwitnesscalc_rs256 -lm
#cgo darwin LDFLAGS: -lc++
#cgo linux LDFLAGS: -lstdc++
#include <stdint.h>
#include <stdlib.h>

extern int         zk_rs256_verify(const char *base_dir);
extern const char *zk_last_error();
*/
import "C"
import (
	"errors"
	"unsafe"
)

func lastError() error {
	msg := C.GoString(C.zk_last_error())
	if msg == "" {
		return errors.New("unknown error")
	}
	return errors.New(msg)
}

// Verify checks the RS256 proof artifacts stored in {baseDir}/keys/.
//
// Reads:
//
//	{baseDir}/keys/rs256_proof.bin
//	{baseDir}/keys/rs256_verifying.key
//
// Returns true if the proof is valid.
func Verify(baseDir string) (bool, error) {
	cBase := C.CString(baseDir)
	defer C.free(unsafe.Pointer(cBase))

	ret := C.zk_rs256_verify(cBase)
	switch {
	case ret > 0:
		return true, nil
	case ret == 0:
		return false, nil
	default:
		return false, lastError()
	}
}
