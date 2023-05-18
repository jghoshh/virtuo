package client

import (
	"fmt"
	"strings"
)

func PrintBanner(message string) {
	bannerChar := "+"
	bannerLength := len(message) + 4
	bannerLine := strings.Repeat(bannerChar, bannerLength)

	fmt.Println(bannerLine)
	fmt.Printf("%s %s %s\n", bannerChar, message, bannerChar)
	fmt.Println(bannerLine)
	fmt.Println()
}

func PrintError(message string) {
	message = "error: " + message
	bannerChar := "*"
	bannerLength := len(message) + 4
	bannerLine := strings.Repeat(bannerChar, bannerLength)

	fmt.Println(bannerLine)
	fmt.Printf("%s %s %s\n", bannerChar, message, bannerChar)
	fmt.Println(bannerLine)
	fmt.Println()
}