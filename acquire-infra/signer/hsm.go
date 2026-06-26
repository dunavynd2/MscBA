package signer

import (
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

// HSM is the interface for KEK operations.
// The KEK never leaves hardware; callers receive only the unwrapped DEK
// and must Wipe it immediately after use.
type HSM interface {
	UnwrapDEK(kekLabel string, wrappedDEK []byte) ([]byte, error)
	Close() error
}

// PKCS11HSM implements HSM against any PKCS#11-compatible token.
//
// Dev default:  SoftHSM2  — /usr/lib/softhsm/libsofthsm2.so
// Production:   Luna HSM  — /usr/safenet/lunaclient/lib/libCryptoki2_64.so
// Override via: HSM_LIB env var
type PKCS11HSM struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

func NewPKCS11HSM(slotID uint, pin string) (*PKCS11HSM, error) {
	lib := os.Getenv("HSM_LIB")
	if lib == "" {
		lib = "/usr/lib/softhsm/libsofthsm2.so"
	}
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", lib)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11 initialize: %w", err)
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("open session slot %d: %w", slotID, err)
	}

	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm login: %w", err)
	}

	return &PKCS11HSM{ctx: ctx, session: session}, nil
}

// UnwrapDEK uses the KEK (identified by label, residing in HSM) to AES-KW unwrap
// the wrappedDEK, briefly exports the DEK value for use in Go AES-GCM, then
// destroys the transient DEK object inside the HSM.
func (h *PKCS11HSM) UnwrapDEK(kekLabel string, wrappedDEK []byte) ([]byte, error) {
	kekHandle, err := h.findKey(kekLabel)
	if err != nil {
		return nil, err
	}

	// AES Key Wrap (RFC 3394) — standard mechanism for key transport
	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil),
	}
	dekTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), // 256-bit DEK
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
	}
	dekHandle, err := h.ctx.UnwrapKey(h.session, mech, kekHandle, wrappedDEK, dekTemplate)
	if err != nil {
		return nil, fmt.Errorf("hsm unwrap dek: %w", err)
	}

	// Export the raw DEK value into Go memory — brief window only
	attrs, err := h.ctx.GetAttributeValue(h.session, dekHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	// Destroy transient DEK object in HSM regardless of export result
	h.ctx.DestroyObject(h.session, dekHandle)
	if err != nil {
		return nil, fmt.Errorf("export dek value: %w", err)
	}

	dek := make([]byte, len(attrs[0].Value))
	copy(dek, attrs[0].Value)
	return dek, nil
}

// GenerateKEK creates a non-extractable AES-256 wrapping key in the HSM under label.
// Returns an error if the label already exists — intentional; re-provisioning requires
// explicit deletion first.  Called once during initial provisioning.
func (h *PKCS11HSM) GenerateKEK(label string) error {
	// Guard: reject if label already present
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := h.ctx.FindObjectsInit(h.session, tmpl); err != nil {
		return fmt.Errorf("find kek init: %w", err)
	}
	objs, _, _ := h.ctx.FindObjects(h.session, 1)
	h.ctx.FindObjectsFinal(h.session)
	if len(objs) > 0 {
		return fmt.Errorf("KEK %q already exists — delete before re-provisioning", label)
	}

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
	}
	keyTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),      // AES-256
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),         // persist across sessions
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),  // never exportable
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
	}
	if _, err := h.ctx.GenerateKey(h.session, mech, keyTmpl); err != nil {
		return fmt.Errorf("generate KEK %q: %w", label, err)
	}
	return nil
}

// WrapDEK imports dek as a transient HSM session object, wraps it under the KEK
// using AES Key Wrap (RFC 3394), then destroys the transient object.
// Used during provisioning to produce the WrappedDEK stored in the wallet file.
func (h *PKCS11HSM) WrapDEK(kekLabel string, dek []byte) ([]byte, error) {
	kekHandle, err := h.findKey(kekLabel)
	if err != nil {
		return nil, err
	}

	// Import the plaintext DEK into the HSM as a session-only object
	importTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, dek),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), // session object only — not persisted
	}
	dekHandle, err := h.ctx.CreateObject(h.session, importTmpl)
	if err != nil {
		return nil, fmt.Errorf("import DEK to HSM: %w", err)
	}
	defer h.ctx.DestroyObject(h.session, dekHandle)

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP, nil),
	}
	wrapped, err := h.ctx.WrapKey(h.session, mech, kekHandle, dekHandle)
	if err != nil {
		return nil, fmt.Errorf("wrap DEK under %q: %w", kekLabel, err)
	}
	return wrapped, nil
}

func (h *PKCS11HSM) findKey(label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := h.ctx.FindObjectsInit(h.session, template); err != nil {
		return 0, fmt.Errorf("find key init: %w", err)
	}
	objs, _, err := h.ctx.FindObjects(h.session, 1)
	h.ctx.FindObjectsFinal(h.session)
	if err != nil {
		return 0, fmt.Errorf("find key %q: %w", label, err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("key %q not found in HSM", label)
	}
	return objs[0], nil
}

func (h *PKCS11HSM) Close() error {
	h.ctx.Logout(h.session)
	h.ctx.CloseSession(h.session)
	h.ctx.Finalize()
	h.ctx.Destroy()
	return nil
}
