package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// TestRegisterResponseParityBetweenNewAndDuplicateEmail closes the per-request
// Set-Cookie enumeration oracle: POST /api/auth/register must emit identical
// status, body, redirect target, and Set-Cookie shape regardless of whether
// the email was new or already registered. Any divergence here re-opens the
// oracle that the pickup-cookie redesign was meant to remove.
func TestRegisterResponseParityBetweenNewAndDuplicateEmail(t *testing.T) {
	app, _ := newOnboardingTestApp(t)

	primaryEmail := "parity-primary@example.com"
	freshEmail := "parity-fresh@example.com"

	// Seed: register primary so a later attempt collides.
	seed := registerRequest(primaryEmail)
	seedResponse := mustAppResponse(t, app, seed)
	assertStatusCode(t, seedResponse, http.StatusSeeOther)

	// First branch: brand-new email, should succeed (creates user + pickup).
	newResponse := mustAppResponse(t, app, registerRequest(freshEmail))
	// Second branch: duplicate email, should silently emit the same shape.
	dupResponse := mustAppResponse(t, app, registerRequest(primaryEmail))

	if newResponse.StatusCode != dupResponse.StatusCode {
		t.Fatalf(
			"status mismatch between new (%d) and duplicate (%d) responses",
			newResponse.StatusCode, dupResponse.StatusCode,
		)
	}

	if newLoc, dupLoc := newResponse.Header.Get("Location"), dupResponse.Header.Get("Location"); newLoc != dupLoc {
		t.Fatalf("Location header mismatch: new=%q duplicate=%q", newLoc, dupLoc)
	}

	newBody := mustReadBodyString(t, newResponse.Body)
	dupBody := mustReadBodyString(t, dupResponse.Body)
	if len(newBody) != len(dupBody) {
		t.Fatalf("body length mismatch: new=%d duplicate=%d", len(newBody), len(dupBody))
	}

	newCookies := indexSetCookies(newResponse)
	dupCookies := indexSetCookies(dupResponse)

	if len(newCookies) != len(dupCookies) {
		t.Fatalf(
			"Set-Cookie count mismatch: new=%d duplicate=%d (new=%v duplicate=%v)",
			len(newCookies), len(dupCookies), cookieNames(newResponse), cookieNames(dupResponse),
		)
	}

	for _, name := range cookieNames(newResponse) {
		newCookie := newCookies[name]
		dupCookie := dupCookies[name]
		if dupCookie == nil {
			t.Fatalf("duplicate response missing cookie %q present in new response", name)
		}
		if len(newCookie.Value) != len(dupCookie.Value) {
			t.Fatalf(
				"cookie %q length mismatch: new=%d duplicate=%d",
				name, len(newCookie.Value), len(dupCookie.Value),
			)
		}
		if newCookie.Path != dupCookie.Path {
			t.Fatalf("cookie %q path mismatch: new=%q duplicate=%q", name, newCookie.Path, dupCookie.Path)
		}
		if newCookie.HttpOnly != dupCookie.HttpOnly {
			t.Fatalf("cookie %q HttpOnly mismatch", name)
		}
		if newCookie.Secure != dupCookie.Secure {
			t.Fatalf("cookie %q Secure mismatch", name)
		}
		if newCookie.SameSite != dupCookie.SameSite {
			t.Fatalf("cookie %q SameSite mismatch", name)
		}
	}

	// Both branches must specifically emit the pickup cookie and must NOT leak
	// the real auth or recovery cookies on the register response itself.
	for label, cookies := range map[string]map[string]*http.Cookie{"new": newCookies, "duplicate": dupCookies} {
		if cookies[registerPickupCookieName] == nil {
			t.Fatalf("%s response missing pickup cookie", label)
		}
		if cookies[authCookieName] != nil {
			t.Fatalf("%s response unexpectedly issued auth cookie", label)
		}
		if cookies[recoveryCodeCookieName] != nil {
			t.Fatalf("%s response unexpectedly issued recovery cookie", label)
		}
	}
}

func registerRequest(email string) *http.Request {
	form := url.Values{
		"email":            {email},
		"password":         {"StrongPass1"},
		"confirm_password": {"StrongPass1"},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept-Language", "en")
	return request
}

func indexSetCookies(response *http.Response) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, cookie := range response.Cookies() {
		out[cookie.Name] = cookie
	}
	return out
}

func cookieNames(response *http.Response) []string {
	names := []string{}
	for _, cookie := range response.Cookies() {
		names = append(names, cookie.Name)
	}
	sort.Strings(names)
	return names
}
