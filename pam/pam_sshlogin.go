// Package main implements pam_sshlogin, a PAM authentication module that
// verifies possession of an SSH private key via an ECDH challenge-response.
//
// Build with: go build -buildmode=c-shared -o pam_sshlogin.so ./pam/
//
// PAM options (specified in the PAM config line, e.g. pam_sshlogin.so otp_len=10):
//
//	otp_len=N    Number of base64url OTP characters to require (default 10, min 6).
//	keys_file=P  Override the authorized_keys path (default: ~/.ssh/authorized_keys).
package main

// #cgo LDFLAGS: -lpam
// #include "pam_shim.h"
// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pqsec/sshlogin/internal/challenge"
	"github.com/pqsec/sshlogin/internal/ecdhutil"
	"github.com/pqsec/sshlogin/internal/keys"
)

// main is required by -buildmode=c-shared but never called.
func main() {}

// options holds the parsed PAM module arguments.
type options struct {
	otpLen   int
	keysFile string
}

//export go_pam_sm_authenticate
func go_pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	opts := parseOptions(argc, argv)

	username := pamGetUser(pamh)
	if username == "" {
		return C.PAM_AUTH_ERR
	}

	keysPath := resolveKeysPath(username, opts.keysFile)
	eligible, err := keys.ParseAuthorizedKeys(keysPath)
	if err != nil || len(eligible) == 0 {
		// No eligible SSH keys found — fall through to next PAM module
		// (e.g. pam_unix.so for password authentication).
		return C.PAM_IGNORE
	}

	entries, err := challenge.Build(eligible)
	if err != nil {
		return C.PAM_AUTH_ERR
	}

	prompt := challenge.Format(entries, opts.otpLen)
	otp, err := pamConv(pamh, prompt)
	if err != nil {
		return C.PAM_AUTH_ERR
	}

	otp = strings.TrimSpace(otp)
	if challenge.VerifyAny(entries, opts.otpLen, otp) {
		return C.PAM_SUCCESS
	}
	return C.PAM_AUTH_ERR
}

// parseOptions extracts otp_len and keys_file from the PAM module argument list.
func parseOptions(argc C.int, argv **C.char) options {
	opts := options{otpLen: ecdhutil.DefaultOTPLen}
	n := int(argc)
	if n == 0 || argv == nil {
		return opts
	}
	// Treat argv as a C array of n pointers.
	cArgs := (*[1 << 10]*C.char)(unsafe.Pointer(argv))[:n:n]
	for _, carg := range cArgs {
		arg := C.GoString(carg)
		switch {
		case strings.HasPrefix(arg, "otp_len="):
			val := strings.TrimPrefix(arg, "otp_len=")
			if v, err := strconv.Atoi(val); err == nil && v >= ecdhutil.MinOTPLen {
				opts.otpLen = v
			}
		case strings.HasPrefix(arg, "keys_file="):
			opts.keysFile = strings.TrimPrefix(arg, "keys_file=")
		}
	}
	return opts
}

// pamGetUser retrieves the PAM user name via get_pam_user helper.
func pamGetUser(pamh *C.pam_handle_t) string {
	cUser := C.get_pam_user(pamh)
	if cUser == nil {
		return ""
	}
	return C.GoString(cUser)
}

// resolveKeysPath returns the authorized_keys path for username.
// If override is non-empty it is returned directly.
// Otherwise the user's home directory is resolved via os/user.Lookup,
// with a fallback to /home/<username>.
func resolveKeysPath(username, override string) string {
	if override != "" {
		return override
	}
	if u, err := user.Lookup(username); err == nil {
		return filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	}
	// Fallback: most Linux systems use /home/<username>
	return filepath.Join("/home", username, ".ssh", "authorized_keys")
}

// pamConv uses the PAM application's conversation function to display prompt
// and read the user's response with echo enabled (PAM_PROMPT_ECHO_ON).
func pamConv(pamh *C.pam_handle_t, prompt string) (string, error) {
	// Retrieve the conversation structure set by the PAM application.
	var convRaw unsafe.Pointer
	if ret := C.pam_get_item(pamh, C.PAM_CONV, &convRaw); ret != C.PAM_SUCCESS {
		return "", fmt.Errorf("pam_get_item(PAM_CONV) failed: %d", ret)
	}
	if convRaw == nil {
		return "", fmt.Errorf("PAM_CONV item is nil")
	}
	conv := (*C.struct_pam_conv)(convRaw)

	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	var cResp *C.char
	if ret := C.do_conv_single(conv, C.PAM_PROMPT_ECHO_ON, cPrompt, &cResp); ret != C.PAM_SUCCESS {
		return "", fmt.Errorf("PAM conversation failed: %d", ret)
	}
	if cResp == nil {
		return "", nil
	}
	result := C.GoString(cResp)
	C.free(unsafe.Pointer(cResp))
	return result, nil
}
