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
		UID: fmt.Sprintf("%016x", uint64(userID)),
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
// string. Wraps the int64 -> uint64 conversion required for unsigned hex
// formatting behind an explicit non-negative check so gosec G115 does not flag
// the conversion and so a clock anomaly (negative nanos) surfaces as an error
// rather than silently overflowing into a far-future date.
func encodePickupExpiryHex(expires time.Time) (string, error) {
	nanos := expires.UnixNano()
	if nanos < 0 {
		return "", errors.New("pickup expiry is before unix epoch")
	}
	// #nosec G115 -- guarded by the negative-check above; the source int64 fits uint64.
	return fmt.Sprintf("%016x", uint64(nanos)), nil
}

// decodePickupExpiry parses the 16-char zero-padded hex back into a UTC time.
// Range-checks uint64 against math.MaxInt64 before narrowing so gosec G115 is
// satisfied and an attacker-supplied EXP of all-Fs returns an error instead of
// silently wrapping to a negative time.
func decodePickupExpiry(encoded string) (time.Time, error) {
	if len(encoded) != 16 {
		return time.Time{}, errors.New("invalid pickup exp")
	}
	nanos, err := strconv.ParseUint(encoded, 16, 64)
	if err != nil {
		return time.Time{}, err
	}
	if nanos > math.MaxInt64 {
		return time.Time{}, errors.New("pickup expiry exceeds int64 range")
	}
	// #nosec G115 -- guarded by the MaxInt64 check above.
	return time.Unix(0, int64(nanos)).UTC(), nil
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
	value, err := strconv.ParseUint(payload.UID, 16, 64)
	if err != nil {
		return 0, err
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
