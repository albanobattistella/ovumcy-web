package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegisterSuccessIssuesPickupCookieAndRedirectsToWelcome(t *testing.T) {
	app, _ := newOnboardingTestApp(t)
	email := "autologin-register@example.com"

	form := url.Values{
		"email":            {email},
		"password":         {"StrongPass1"},
		"confirm_password": {"StrongPass1"},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/register", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept-Language", "en")

	response, err := app.Test(request, -1)
	if err != nil {
		t.Fatalf("register success request failed: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected status 303, got %d", response.StatusCode)
	}
	if location := response.Header.Get("Location"); location != "/register/welcome" {
		t.Fatalf("expected redirect to /register/welcome, got %q", location)
	}

	if cookie := responseCookieValue(response.Cookies(), authCookieName); cookie != "" {
		t.Fatalf("expected no auth cookie on POST register; got %q", cookie)
	}
	if cookie := responseCookieValue(response.Cookies(), recoveryCodeCookieName); cookie != "" {
		t.Fatalf("expected no recovery cookie on POST register; got %q", cookie)
	}
	if pickup := responseCookieValue(response.Cookies(), registerPickupCookieName); pickup == "" {
		t.Fatalf("expected pickup cookie in register response")
	}
}
