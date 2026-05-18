package services

import "strings"

func IsOnboardingPath(path string) bool {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "/onboarding" {
		return true
	}
	return strings.HasPrefix(cleanPath, "/api/v1/onboarding/")
}

func ShouldEnforceOnboardingAccess(path string) bool {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "/api/v1/sessions/current" {
		return false
	}
	return !IsOnboardingPath(cleanPath)
}
