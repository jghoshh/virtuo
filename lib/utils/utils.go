package utils

import (

	"regexp"
	"fmt"
	"strings"

	)

// validateEmail takes an email string as input and returns a boolean indicating whether the input is a valid email address.
func ValidateEmail(email string) bool {
	const emailPattern = `^(?i)[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}$`
	matched, err := regexp.MatchString(emailPattern, email)
	return err == nil && matched
}

// validatePassword takes a password string as input and returns a boolean indicating whether the input is a valid password.
func ValidatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	containsLetter, _ := regexp.MatchString(`[a-zA-Z]`, password)
	containsNumber, _ := regexp.MatchString(`[0-9]`, password)
	return containsLetter && containsNumber
}

func PrintError(message string) {
	message = "ERROR: " + message
	bannerChar := "="
	bannerLength := len(message) + 4
	bannerLine := strings.Repeat(bannerChar, bannerLength)

	fmt.Println(bannerLine)
	fmt.Printf("%s %s %s\n", bannerChar, message, bannerChar)
	fmt.Println(bannerLine)
	fmt.Println()
}