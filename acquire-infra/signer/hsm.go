package signer

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// Luna HSM PKCS#11 library path (SafeNet/Thales Luna Network HSM)
const lunaLibPath = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"

// HSM is the interface for KEK operations.
// The KEK never leaves hardware; callers receive only the unwrapped DEK
// and must Wipe it immediately after use.
type HSM interface {
	UnwrapDEK(kekLabel string, wrappedDEK []byte) ([]byte, error)
	Close() error
}

// LunaHSM implements HSM against a SafeNet Luna HSM via PKCS#11.
type LunaHSM struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

func NewLunaHSM(slotID uint, pin string) (*LunaHSM, error) {
	ctx := pkcs11.New(lunaLibPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", lunaLibPath)
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

	return &LunaHSM{ctx: ctx, session: session}, nil
}

// UnwrapDEK uses the KEK (identified by label, residing in HSM) to AES-KW unwrap
// the wrappedDEK, briefly exports the DEK value for use in Go AES-GCM, then
// destroys the transient DEK object inside the HSM.
func (h *LunaHSM) UnwrapDEK(kekLabel string, wrappedDEK []byte) ([]byte, error) {
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

func (h *LunaHSM) findKey(label string) (pkcs11.ObjectHandle, error) {
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

func (h *LunaHSM) Close() error {
	h.ctx.Logout(h.session)
	h.ctx.CloseSession(h.session)
	h.ctx.Finalize()
	h.ctx.Destroy()
	return nil
}
