package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func newPickupTestHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		secretKey:    []byte("0123456789abcdef0123456789abcdef"),
		cookieSecure: false,
	}
}

func TestNewRegisterPickupPayloadShape(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	payload, err := newRegisterPickupPayload(now, 42, "OVUM-AAAA-BBBB-CCCC")
	if err != nil {
		t.Fatalf("newRegisterPickupPayload: %v", err)
	}
	if len(payload.UID) != 16 {
		t.Fatalf("expected UID length 16, got %d (%q)", len(payload.UID), payload.UID)
	}
	if payload.UID != "000000000000002a" {
		t.Fatalf("expected hex uid for 42, got %q", payload.UID)
	}
	if payload.RC != "OVUM-AAAA-BBBB-CCCC" {
		t.Fatalf("expected RC preserved, got %q", payload.RC)
	}
	if len(payload.EXP) != 16 {
		t.Fatalf("expected EXP length 16, got %d (%q)", len(payload.EXP), payload.EXP)
	}
	if !payload.validAt(now) {
		t.Fatal("expected fresh payload to be valid")
	}
	if payload.validAt(now.Add(registerPickupCookieTTL + time.Second)) {
		t.Fatal("expected payload past TTL to be invalid")
	}
}

func TestNewRegisterPickupPayloadRejectsZeroUserID(t *testing.T) {
	t.Parallel()

	if _, err := newRegisterPickupPayload(time.Now(), 0, "OVUM-AAAA-BBBB-CCCC"); err == nil {
		t.Fatal("expected error for userID=0")
	}
}

func TestNewRegisterPickupPayloadRejectsBadRecoveryCode(t *testing.T) {
	t.Parallel()

	for _, badCode := range []string{
		"",
		"too-short",
		"NOT-AAAA-BBBB-CCCC",
		"OVUM-XXXXX-BBBB-CCCC",
	} {
		if _, err := newRegisterPickupPayload(time.Now(), 1, badCode); err == nil {
			t.Fatalf("expected error for recovery code %q", badCode)
		}
	}
}

// TestRegisterPickupRealAndDecoyMatchInLength is the load-bearing check for
// the per-request enumeration oracle closure: real and decoy ciphertexts
// must have identical lengths so an attacker watching Set-Cookie size cannot
// distinguish branches. Built on plaintext serialization shape; if anyone
// touches the payload struct without preserving fixed-width fields, this
// test will catch it.
func TestRegisterPickupRealAndDecoyMatchInLength(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)

	real1, err := newRegisterPickupPayload(now, 1, "OVUM-AAAA-BBBB-CCCC")
	if err != nil {
		t.Fatalf("real payload (uid=1): %v", err)
	}
	realBig, err := newRegisterPickupPayload(now, 0xDEADBEEF12345678, "OVUM-1234-5678-9ABC")
	if err != nil {
		t.Fatalf("real payload (uid=big): %v", err)
	}
	decoy, err := newRegisterPickupDecoyPayload(now)
	if err != nil {
		t.Fatalf("decoy payload: %v", err)
	}

	realBytes, err := json.Marshal(real1)
	if err != nil {
		t.Fatalf("marshal real1: %v", err)
	}
	realBigBytes, err := json.Marshal(realBig)
	if err != nil {
		t.Fatalf("marshal realBig: %v", err)
	}
	decoyBytes, err := json.Marshal(decoy)
	if err != nil {
		t.Fatalf("marshal decoy: %v", err)
	}

	if len(realBytes) != len(decoyBytes) || len(realBytes) != len(realBigBytes) {
		t.Fatalf(
			"serialized length mismatch: real1=%d realBig=%d decoy=%d",
			len(realBytes), len(realBigBytes), len(decoyBytes),
		)
	}
}

func TestSetAndPopRegisterPickupCookieRoundTrip(t *testing.T) {
	t.Parallel()

	handler := newPickupTestHandler(t)
	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	original, err := newRegisterPickupPayload(now, 99, "OVUM-AAAA-BBBB-CCCC")
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}

	var cookieValue string
	setApp := fiber.New()
	setApp.Get("/set", func(c *fiber.Ctx) error {
		if err := handler.setRegisterPickupCookie(c, original); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}
		return c.SendStatus(fiber.StatusNoContent)
	})
	setResp, err := setApp.Test(httptest.NewRequest("GET", "/set", nil), -1)
	if err != nil {
		t.Fatalf("set request: %v", err)
	}
	defer setResp.Body.Close()
	for _, c := range setResp.Cookies() {
		if c.Name == registerPickupCookieName {
			cookieValue = c.Value
		}
	}
	if cookieValue == "" {
		t.Fatal("expected pickup cookie to be set")
	}

	popApp := fiber.New()
	var popped registerPickupPayload
	var poppedOK bool
	popApp.Get("/welcome", func(c *fiber.Ctx) error {
		popped, poppedOK = handler.popRegisterPickupCookie(c)
		return c.SendStatus(fiber.StatusNoContent)
	})
	popReq := httptest.NewRequest("GET", "/welcome", nil)
	popReq.Header.Set("Cookie", registerPickupCookieName+"="+cookieValue)
	popResp, err := popApp.Test(popReq, -1)
	if err != nil {
		t.Fatalf("pop request: %v", err)
	}
	defer popResp.Body.Close()

	if !poppedOK {
		t.Fatal("expected popRegisterPickupCookie to succeed")
	}
	if popped.UID != original.UID || popped.RC != original.RC || popped.EXP != original.EXP {
		t.Fatalf("payload not preserved across round-trip: got %+v want %+v", popped, original)
	}
}

func TestPopRegisterPickupCookieWrongKeyReturnsEmpty(t *testing.T) {
	t.Parallel()

	signer := &Handler{
		secretKey:    []byte("0123456789abcdef0123456789abcdef"),
		cookieSecure: false,
	}
	verifier := &Handler{
		secretKey:    []byte("fedcba9876543210fedcba9876543210"),
		cookieSecure: false,
	}

	now := time.Date(2026, 5, 13, 10, 0, 0, 0, time.UTC)
	payload, err := newRegisterPickupPayload(now, 5, "OVUM-AAAA-BBBB-CCCC")
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}

	var cookieValue string
	setApp := fiber.New()
	setApp.Get("/set", func(c *fiber.Ctx) error {
		if err := signer.setRegisterPickupCookie(c, payload); err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}
		return c.SendStatus(fiber.StatusNoContent)
	})
	setResp, err := setApp.Test(httptest.NewRequest("GET", "/set", nil), -1)
	if err != nil {
		t.Fatalf("set request: %v", err)
	}
	defer setResp.Body.Close()
	for _, c := range setResp.Cookies() {
		if c.Name == registerPickupCookieName {
			cookieValue = c.Value
		}
	}

	popApp := fiber.New()
	var popped registerPickupPayload
	var poppedOK bool
	popApp.Get("/welcome", func(c *fiber.Ctx) error {
		popped, poppedOK = verifier.popRegisterPickupCookie(c)
		return c.SendStatus(fiber.StatusNoContent)
	})
	popReq := httptest.NewRequest("GET", "/welcome", nil)
	popReq.Header.Set("Cookie", registerPickupCookieName+"="+cookieValue)
	popResp, err := popApp.Test(popReq, -1)
	if err != nil {
		t.Fatalf("pop request: %v", err)
	}
	defer popResp.Body.Close()

	if poppedOK {
		t.Fatalf("expected wrong-key pop to fail, got %+v", popped)
	}
}

func TestPopRegisterPickupCookieTamperedValueReturnsEmpty(t *testing.T) {
	t.Parallel()

	handler := newPickupTestHandler(t)
	popApp := fiber.New()
	var poppedOK bool
	popApp.Get("/welcome", func(c *fiber.Ctx) error {
		_, poppedOK = handler.popRegisterPickupCookie(c)
		return c.SendStatus(fiber.StatusNoContent)
	})

	popReq := httptest.NewRequest("GET", "/welcome", nil)
	popReq.Header.Set("Cookie", registerPickupCookieName+"=v2.garbage-payload")
	popResp, err := popApp.Test(popReq, -1)
	if err != nil {
		t.Fatalf("pop request: %v", err)
	}
	defer popResp.Body.Close()

	if poppedOK {
		t.Fatal("expected tampered pickup cookie to be rejected")
	}
}
