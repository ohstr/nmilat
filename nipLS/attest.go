package nipLS

import (
	"context"

	"github.com/ohstr/nmilat/nipOA"
	"github.com/ohstr/nmilat/utils"
)

// AttestFunc decides one attestation request: subordinate is the key to
// attest (lowercase hex), cond its parsed conditions (cond.Raw is what will
// be signed, verbatim). nil allows it; return Deny to refuse.
type AttestFunc func(ctx context.Context, req *Request, subordinate string, cond nipOA.Conditions) error

// AttestationMethod answers nipOA.MethodSignAttestation with signer, for
// ServerConfig.Methods:
//
//	Methods: map[string]nipLS.Handler{
//		nipOA.MethodSignAttestation: nipLS.AttestationMethod(signer, authorize),
//	}
//
// Custom methods bypass ServerConfig.Policy, so authorize is this method's
// whole gate, and a nil authorize refuses every request: attesting is
// denied unless a rule allows it.
func AttestationMethod(signer nipOA.Signer, authorize AttestFunc) Handler {
	return func(ctx context.Context, req *Request) (string, error) {
		if len(req.Params) != 2 {
			return "", Invalid(nipOA.MethodSignAttestation + " requires [subordinate pubkey, conditions]")
		}
		subordinate, raw := req.Params[0], req.Params[1]
		if err := utils.Validate32Key(subordinate); err != nil {
			return "", Invalid("invalid subordinate pubkey")
		}
		cond, err := nipOA.ParseConditions(raw)
		if err != nil {
			return "", Invalid(err.Error())
		}
		if authorize == nil {
			return "", Deny("attestations are not allowed")
		}
		if err := authorize(ctx, req, subordinate, cond); err != nil {
			return "", err
		}
		tag, err := nipOA.Sign(ctx, signer, subordinate, raw)
		if err != nil {
			return "", err
		}
		return tag[3], nil
	}
}
