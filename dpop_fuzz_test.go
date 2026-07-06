package sdk

import (
	"context"
	"testing"
)

// FuzzDPoPValidate feeds arbitrary bytes into the resource-server DPoP
// validator. The contract is narrow: validateString must never panic or
// leak a goroutine, regardless of input shape. All valid rejects return
// a typed error; malformed input should short-circuit without crashing.
//
// Seeds include a valid proof (from the unit test builder), an empty
// string, and common byte-sequence edge cases likely to trip base64 or
// JSON parsing.
func FuzzDPoPValidate(f *testing.F) {
	// Valid seed -- generated at fuzz startup so we don't depend on a
	// hardcoded token whose iat would already be stale.
	validProof := newTestProofBuilder(f).sign(proofOpts{
		htm: "POST",
		htu: "http://x/rpc",
	})
	f.Add(validProof, "POST", "http://x/rpc", "")
	f.Add("", "POST", "http://x/rpc", "")
	f.Add("not-a-jwt", "POST", "http://x/rpc", "")
	f.Add(".", "POST", "http://x/rpc", "")
	f.Add("..", "POST", "http://x/rpc", "")
	f.Add("aaaa.bbbb.cccc", "POST", "http://x/rpc", "")
	f.Add("\x00\x00\x00", "POST", "http://x/rpc", "")
	f.Add(validProof, "", "", "")
	f.Add(validProof, "POST", "", "not-a-jkt")

	v := NewDPoPValidator()
	f.Fuzz(func(t *testing.T, raw, method, uri, expectedJKT string) {
		// The ONLY requirement: never panic. Any error return is fine.
		_, _ = v.validateString(context.Background(), raw, method, uri, expectedJKT, "")
	})
}
