package api

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSettingsClearDataUsesFlashSuccessOnRedirect(t *testing.T) {
	assertSettingsFlashSuccessScenario(t, http.MethodPost, "/api/v1/users/current/data-wipe", url.Values{
		"password": {"StrongPass1"},
	}, "All tracking data cleared successfully.")
}

func TestSettingsCycleUpdateUsesFlashSuccessOnRedirect(t *testing.T) {
	form := url.Values{
		"cycle_length":     {"29"},
		"period_length":    {"6"},
		"auto_period_fill": {"true"},
	}
	assertSettingsFlashSuccessScenario(t, http.MethodPatch, "/api/v1/users/current/cycle", form, "Cycle settings updated successfully.")
}

func TestSettingsInterfaceUpdateUsesFlashSuccessOnRedirect(t *testing.T) {
	form := url.Values{
		"language": {"de"},
		"theme":    {"dark"},
	}
	assertSettingsFlashSuccessScenario(t, http.MethodPatch, "/api/v1/users/current/interface", form, "Interface settings updated.")
}

func TestSettingsPasswordChangeUsesFlashSuccessOnRedirect(t *testing.T) {
	form := url.Values{
		"current_password": {"StrongPass1"},
		"new_password":     {"EvenStronger2"},
		"confirm_password": {"EvenStronger2"},
	}
	assertSettingsFlashSuccessScenario(t, http.MethodPut, "/api/v1/users/current/password", form, "Password changed successfully.")
}
