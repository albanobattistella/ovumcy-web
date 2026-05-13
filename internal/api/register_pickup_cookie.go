package api

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// registerPickupCookieTTL caps how long the sealed register-pickup cookie is
// honored after POST /api/auth/register. Short on purpose so a stale pickup
// cannot be replayed minutes after the fact, but long enough to absorb the
// natural 303 follow-up plus a brief stall.
const registerPickupCookieTTL = 5 * time.Minute

// registerPickupPayload carries the state needed to materialize an auth
// session and reveal a recovery code at GET /register/welcome. The payload is
// serialized to JSON with FIXED-WIDTH string fields so that the resulting
// ciphertext is byte-identical in length between a real new-user payload and
// a decoy payload for a duplicate-email collision. This is what closes the
// per-request Set-Cookie enumeration oracle on POST /api/auth/register.
type registerPickupPayload struct {
	UID string `json:"uid"` // 16 hex chars: uint64 user id (zero-padded) or random bytes for decoy
	RC  string `json:"rc"`  // 19 chars: OVUM-XXXX-XXXX-XXXX recovery code (real or decoy in matching shape)
	EXP string `json:"exp"` // 16 hex chars: int64 unix nanos of expiry
}

func newRegisterPickupPayload(now time.Time, userID uint, recoveryCode string) (registerPickupPayload, error) {
	if userID == 0 {
		return registerPickupPayload{}, errors.New("pickup payload requires user id")
	}
	rc := strings.TrimSpace(recoveryCode)
	if !validPickupRecoveryCodeShape(rc) {
		return registerPickupPayload{}, errors.New("pickup payload requires OVUM-XXXX-XXXX-XXXX recovery code")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresHex, err := encodePickupExpiryHex(now.UTC().Add(registerPickupCookieTTL))
	if err != nil {
		return registerPickupPayload{}, err
	}
	return registerPickupPayload{
		UID: fmt.Sprintf("%016x", userID),
		RC:  rc,
		EXP: expiresHex,
	}, nil
}

// newRegisterPickupDecoyPayload returns a payload structurally indistinguishable
// from newRegisterPickupPayload but whose decrypted contents will never resolve
// to a real user. Use for the duplicate-email branch so that POST register
// emits the same Set-Cookie shape regardless of email existence.
func newRegisterPickupDecoyPayload(now time.Time) (registerPickupPayload, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	uidBytes := make([]byte, 8)
	if _, err := rand.Read(uidBytes); err != nil {
		return registerPickupPayload{}, err
	}
	rcBytes := make([]byte, 6)
	if _, err := rand.Read(rcBytes); err != nil {
		return registerPickupPayload{}, err
	}
	rcHex := strings.ToUpper(hex.EncodeToString(rcBytes))
	rc := "OVUM-" + rcHex[0:4] + "-" + rcHex[4:8] + "-" + rcHex[8:12]
	expiresHex, err := encodePickupExpiryHex(now.UTC().Add(registerPickupCookieTTL))
	if err != nil {
		return registerPickupPayload{}, err
	}
	return registerPickupPayload{
		UID: fmt.Sprintf("%016x", binary.BigEndian.Uint64(uidBytes)),
		RC:  rc,
		EXP: expiresHex,
	}, nil
}

// encodePickupExpiryHex renders the pickup expiry as a 16-char zero-padded hex
// string. Surfaces a clock anomaly (negative unix nanos) as an error instead
// of silently formatting as "-<hex>" and breaking the fixed-width invariant
// that the response-parity test depends on.
func encodePickupExpiryHex(expires time.Time) (string, error) {
	nanos := expires.UnixNano()
	if nanos < 0 {
		return "", errors.New("pickup expiry is before unix epoch")
	}
	return fmt.Sprintf("%016x", nanos), nil
}

// decodePickupExpiry parses the 16-char zero-padded hex back into a UTC time.
// strconv.ParseInt with bitSize=64 rejects values that do not fit in int64
// (an attacker-supplied "ffff...ff" returns an error), so no narrowing
// conversion is needed.
func decodePickupExpiry(encoded string) (time.Time, error) {
	if len(encoded) != 16 {
		return time.Time{}, errors.New("invalid pickup exp")
	}
	nanos, err := strconv.ParseInt(encoded, 16, 64)
	if err != nil {
		return time.Time{}, err
	}
	if nanos < 0 {
		return time.Time{}, errors.New("invalid pickup exp")
	}
	return time.Unix(0, nanos).UTC(), nil
}

func validPickupRecoveryCodeShape(code string) bool {
	if len(code) != 19 {
		return false
	}
	if !strings.HasPrefix(code, "OVUM-") {
		return false
	}
	if code[9] != '-' || code[14] != '-' {
		return false
	}
	return true
}

func (payload registerPickupPayload) userID() (uint, error) {
	if len(payload.UID) != 16 {
		return 0, errors.New("invalid pickup uid")
	}
	// Parse as uint64, then explicitly bound-check against the platform
	// uint width before narrowing. The guard is a no-op on 64-bit
	// (math.MaxUint == math.MaxUint64) but catches the 32-bit case where
	// a 16-hex-char encoded value could overflow uint=uint32. The check
	// also satisfies CodeQL's go/incorrect-integer-conversion query, which
	// flags uint64->uint narrowing without a visible upper bound regardless
	// of the bitSize passed to ParseUint.
	value, err := strconv.ParseUint(payload.UID, 16, 64)
	if err != nil {
		return 0, err
	}
	if value > math.MaxUint {
		return 0, errors.New("pickup uid exceeds platform uint width")
	}
	return uint(value), nil
}

func (payload registerPickupPayload) expiresAt() (time.Time, error) {
	return decodePickupExpiry(payload.EXP)
}

func (payload registerPickupPayload) validAt(now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiry, err := payload.expiresAt()
	if err != nil || !expiry.After(now.UTC()) {
		return false
	}
	if !validPickupRecoveryCodeShape(strings.TrimSpace(payload.RC)) {
		return false
	}
	return len(payload.UID) == 16
}

func (handler *Handler) setRegisterPickupCookie(c *fiber.Ctx, payload registerPickupPayload) error {
	if !payload.validAt(time.Now()) {
		return errors.New("pickup cookie payload is invalid")
	}

	serialized, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	codec, err := newSecureCookieCodec(handler.secretKey)
	if err != nil {
		return err
	}
	encoded, err := codec.seal(registerPickupCookieName, serialized)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     registerPickupCookieName,
		Value:    encoded,
		Path:     "/",
		HTTPOnly: true,
		Secure:   handler.cookieSecure,
		SameSite: "Lax",
		Expires:  time.Now().Add(registerPickupCookieTTL),
	})
	return nil
}

func (handler *Handler) popRegisterPickupCookie(c *fiber.Ctx) (registerPickupPayload, bool) {
	raw := strings.TrimSpace(c.Cookies(registerPickupCookieName))
	if raw == "" {
		return registerPickupPayload{}, false
	}
	handler.clearRegisterPickupCookie(c)

	codec, err := newSecureCookieCodec(handler.secretKey)
	if err != nil {
		return registerPickupPayload{}, false
	}
	decoded, err := codec.open(registerPickupCookieName, raw)
	if err != nil {
		return registerPickupPayload{}, false
	}

	payload := registerPickupPayload{}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return registerPickupPayload{}, false
	}
	if !payload.validAt(time.Now()) {
		return registerPickupPayload{}, false
	}
	return payload, true
}

func (handler *Handler) clearRegisterPickupCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     registerPickupCookieName,
		Value:    "",
		Path:     "/",
		HTTPOnly: true,
		Secure:   handler.cookieSecure,
		SameSite: "Lax",
		Expires:  time.Now().Add(-1 * time.Hour),
	})
}
