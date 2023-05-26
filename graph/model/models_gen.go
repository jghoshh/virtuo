// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package model

type AuthPayload struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

type ResetPasswordInput struct {
	Email       string `json:"email"`
	NewPassword string `json:"newPassword"`
}

type UpdateUserInput struct {
	CurrentPassword string  `json:"currentPassword"`
	NewUsername     *string `json:"newUsername,omitempty"`
	NewEmail        *string `json:"newEmail,omitempty"`
	NewPassword     *string `json:"newPassword,omitempty"`
}

type User struct {
	ID             string   `json:"id"`
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	EmailConfirmed bool     `json:"emailConfirmed"`
	Points         int      `json:"points"`
	LevelID        string   `json:"levelID"`
	GroupIDs       []string `json:"groupIDs,omitempty"`
	Streak         int      `json:"streak"`
}

type UserInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}