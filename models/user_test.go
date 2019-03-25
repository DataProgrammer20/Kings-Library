package models_test

import (
	. "./"
	"testing"
)

func TestAuthenticationFailsWithIncorrectPassword(t *testing.T) {
	user := NewUser("wkingsley15@gmail.com", "password")
	if user.Authentication("wrong") {
		t.Error("Authenticate should return false for incorrect password")
	}
}

func TestAuthenticationSucceedsWithCorrectPassword(t *testing.T) {
	user := NewUser("wkingsley15@gmail.com", "password")
	if !user.Authentication("password") {
		t.Errorf("Authenticate should return true for correct password")
	}
}
