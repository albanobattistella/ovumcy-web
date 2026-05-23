package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovumcy/ovumcy-web/internal/models"
)

// Basic identity / catalog handler smoke regressions. These cover the
// always-on "who am I", "is this app up", and "what symptoms do I have"
// endpoints — small surfaces but each is a public contract: a wrapper
// or a healthcheck probe relies on the response shape staying stable.

func TestHealthEndpointReturnsOKJSON(t *testing.T) {
	app, _ := newOnboardingTestApp(t)

	response := mustAppResponse(t, app, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	assertStatusCode(t, response, http.StatusOK)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read healthz body: %v", err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode healthz JSON %q: %v", body, err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", payload["status"])
	}
}

func TestGetCurrentUserWithoutAuthCookieReturnsUnauthorized(t *testing.T) {
	app, _ := newOnboardingTestApp(t)

	response := mustAppResponse(t, app, httptest.NewRequest(http.MethodGet, "/api/v1/users/current", nil))
	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 401 or redirect for unauthenticated current-user, got %d", response.StatusCode)
	}
}

// TestGetCurrentUserReturnsMinimalIdentityShape locks the public contract a
// wrapper or external client needs to identify the session and decide what
// mutating calls it can make. The handler intentionally never includes
// sensitive fields (password/recovery hashes, TOTP secret), so this test
// also blocks accidental field leaks added by a future refactor.
func TestGetCurrentUserReturnsMinimalIdentityShape(t *testing.T) {
	app, database := newOnboardingTestApp(t)
	user := createOnboardingTestUser(t, database, "current-user-shape@example.com", "StrongPass1", true)
	if err := database.Model(&user).Updates(map[string]any{
		"display_name":         "Owner Display",
		"must_change_password": false,
	}).Error; err != nil {
		t.Fatalf("seed display fields: %v", err)
	}
	authCookie := loginAndExtractAuthCookie(t, app, user.Email, "StrongPass1")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/users/current", nil)
	request.Header.Set("Cookie", authCookie)
	response := mustAppResponse(t, app, request)
	assertStatusCode(t, response, http.StatusOK)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read current-user body: %v", err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode current-user JSON %q: %v", body, err)
	}

	expectedFields := []string{"id", "email", "display_name", "role", "onboarding_completed", "local_auth_enabled", "must_change_password"}
	for _, field := range expectedFields {
		if _, ok := payload[field]; !ok {
			t.Fatalf("expected current-user payload to expose %q, got %v", field, payload)
		}
	}
	for _, leakedField := range []string{"password_hash", "password", "recovery_code_hash", "recovery_code", "totp_secret", "totp_secret_encrypted"} {
		if _, ok := payload[leakedField]; ok {
			t.Fatalf("did not expect current-user payload to expose %q (sensitive field leak): %v", leakedField, payload)
		}
	}
	if payload["email"] != user.Email {
		t.Fatalf("expected email %q, got %v", user.Email, payload["email"])
	}
	if payload["role"] != string(models.RoleOwner) {
		t.Fatalf("expected role %q, got %v", models.RoleOwner, payload["role"])
	}
	bodyString := string(body)
	for _, leak := range []string{"$2a$", "$2b$", "totp_secret"} {
		if strings.Contains(bodyString, leak) {
			t.Fatalf("current-user response contained sensitive token %q: %q", leak, bodyString)
		}
	}
}

func TestGetSymptomsWithoutAuthCookieReturnsUnauthorized(t *testing.T) {
	app, _ := newOnboardingTestApp(t)

	response := mustAppResponse(t, app, httptest.NewRequest(http.MethodGet, "/api/v1/symptoms", nil))
	if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 401 or redirect for unauthenticated symptoms list, got %d", response.StatusCode)
	}
}

// TestGetSymptomsReturnsBuiltinCatalogForOwner locks the catalog content the
// frontend keys off: the builtin "Cramps" symptom (seeded for every owner)
// must appear in the response. Asserting a known catalog *name* survives
// future struct-tag renames or JSON-shape refactors, unlike asserting Go
// struct field keys.
func TestGetSymptomsReturnsBuiltinCatalogForOwner(t *testing.T) {
	app, database := newOnboardingTestApp(t)
	user := createOnboardingTestUser(t, database, "symptoms-catalog@example.com", "StrongPass1", true)
	authCookie := loginAndExtractAuthCookie(t, app, user.Email, "StrongPass1")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/symptoms", nil)
	request.Header.Set("Cookie", authCookie)
	response := mustAppResponse(t, app, request)
	assertStatusCode(t, response, http.StatusOK)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read symptoms body: %v", err)
	}
	if !strings.Contains(string(body), `"Cramps"`) && !strings.Contains(string(body), `"name":"Cramps"`) {
		t.Fatalf("expected builtin 'Cramps' symptom in owner catalog, got %q", body)
	}
}

// TestGetSymptomsDoesNotLeakOtherOwnerCustomSymptom locks the owner-scoping
// privacy invariant. Owner A creates a uniquely-named custom symptom; owner
// B (separate account) listing /api/v1/symptoms must not see it. Failure
// here would mean the symptom catalog leaks PHI-adjacent labels across
// accounts.
func TestGetSymptomsDoesNotLeakOtherOwnerCustomSymptom(t *testing.T) {
	app, database := newOnboardingTestApp(t)
	ownerA := createOnboardingTestUser(t, database, "symptoms-owner-a@example.com", "StrongPass1", true)
	ownerB := createOnboardingTestUser(t, database, "symptoms-owner-b@example.com", "StrongPass1", true)

	const ownerASymptomName = "OwnerA-SecretMarker-9f1e2"
	if err := database.Create(&models.SymptomType{
		UserID: ownerA.ID,
		Name:   ownerASymptomName,
		Icon:   "🔒",
		Color:  "#112233",
	}).Error; err != nil {
		t.Fatalf("seed owner A custom symptom: %v", err)
	}

	authCookieB := loginAndExtractAuthCookie(t, app, ownerB.Email, "StrongPass1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/symptoms", nil)
	request.Header.Set("Cookie", authCookieB)
	response := mustAppResponse(t, app, request)
	assertStatusCode(t, response, http.StatusOK)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read symptoms body: %v", err)
	}
	if strings.Contains(string(body), ownerASymptomName) {
		t.Fatalf("owner B's symptoms catalog leaked owner A's custom symptom %q: %s", ownerASymptomName, body)
	}
}
