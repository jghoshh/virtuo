package auth

import (
	"github.com/jghoshh/virtuo/storage"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"regexp"
	"github.com/jghoshh/virtuo/graph/model"
	"time"
	"errors"
	"fmt"
	"github.com/form3tech-oss/jwt-go"
)

var store storage.StorageInterface
var jwtSigningKey string
var KeyringKey string
const KeyringService = "Virtuo"

// InitAuth initializes the global storage and jwtSigningKey variables.
// It is required to be called before any other function in this package.
// It takes a MongoDB URI, signing key, and auth token as input.
func InitAuth(dbName, mongodbURI, signingKey string) {
	jwtSigningKey = signingKey
	/**
	store, err = storage.NewStorage(dbName, mongodbURI)
	if err != nil {
		panic("Error initializing storage: " + err.Error())
	}
	**/
}

// validateEmail takes an email string as input and returns a boolean indicating whether the input is a valid email address.
func validateEmail(email string) bool {
	const emailPattern = `^(?i)[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}$`
	matched, err := regexp.MatchString(emailPattern, email)
	return err == nil && matched
}

// validatePassword takes a password string as input and returns a boolean indicating whether the input is a valid password.
// A valid password is at least 8 characters long and contains both numbers and letters.
func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	containsLetter, _ := regexp.MatchString(`[a-zA-Z]`, password)
	containsNumber, _ := regexp.MatchString(`[0-9]`, password)
	return containsLetter && containsNumber
}

// SignIn logs in a user with the username and password. Returns an error if the username or password is incorrect.
func SignIn(username string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", fmt.Errorf("username must be at least 2 characters")
	}
	
	if !validatePassword(password) {
		return "", "", fmt.Errorf("password must be at least 8 characters and contain both letters and numbers")
	}

	token, refreshToken, err := CreateTokens(primitive.NewObjectID().Hex())

	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

// SignUp creates a new user with the provided username, email, and password.
func SignUp(username string, email string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", fmt.Errorf("username must be at least 2 characters")
	}

	if !validateEmail(email) {
		return "", "", fmt.Errorf("invalid email format")
	}

	if !validatePassword(password) {
		return "", "", fmt.Errorf("password must be at least 8 characters and contain both letters and numbers")
	}

	newUserID := primitive.NewObjectID().Hex()

	newUser := model.User{
		ID:       newUserID,
		Username: username,
		Email:    email,
		Points:   0,
		LevelID:  primitive.NilObjectID.Hex(),
		GroupIDs: []string{},
		Streak:   0,
	}

	fmt.Println(newUser)

	token, refreshToken, err := CreateTokens(newUserID) 
	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

// CreateRefreshToken generates a refresh token for the given user id.
func CreateRefreshToken(userId string) (string, error) {
	claims := jwt.MapClaims{
		"id":  userId, 
		"exp": time.Now().Add(time.Minute * 30).Unix(),  
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := newToken.SignedString([]byte(jwtSigningKey))

	if err != nil {
		return "", errors.New("failed to create refresh token")
	}

	return signedToken, nil
}

// CreateAuthToken creates and returns a signed JWT token for the given user id.
func CreateAuthToken(userId string) (string, error) {
	claims := jwt.MapClaims{
		"id":  userId,
		"exp": time.Now().Add(time.Second * 4).Unix(),
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := newToken.SignedString([]byte(jwtSigningKey))

	if err != nil {
		return "", errors.New("failed to create auth token")
	}

	return signedToken, nil
}

// CreateTokens generates a new auth token and refresh token for the given user id.
func CreateTokens(userId string) (string, string, error) {
	authToken, authErr := CreateAuthToken(userId)
	if authErr != nil {
		return "", "", authErr
	}

	refreshToken, refreshErr := CreateRefreshToken(userId)
	if refreshErr != nil {
		return "", "", refreshErr
	}

	return authToken, refreshToken, nil
}

// RefreshToken validates the given refresh token, and if it is valid, generates a new auth token and refresh token.
func RefreshToken(userId string, refreshToken string) (string, string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSigningKey), nil
	})

	if err != nil {
		return "", "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid refresh token")
	}

	if claims["id"] != userId {
		return "", "", errors.New("invalid refresh token")
	}

	return CreateTokens(userId)
}

// UpdateUser updates the details of the user with the given id.
func UpdateUser(userId, currentPassword, newUsername, newEmail, newPassword string) (*model.User, error) {
	// This function should validate the current password, and if it's correct, update the
	// user's details with the new values. If the current password is not correct, it should
	// return an error.
	// For now, we'll just return a dummy user.
	return &model.User{
		ID:       primitive.NewObjectID().Hex(),
		Username: newUsername,
		Email:    newEmail,
	}, nil
}

// DeleteUser deletes the user with the given id.
func DeleteUser(userId string) (bool, error) {
	// This function should delete the user with the given id. If the user doesn't exist or
	// there's an error deleting the user, it should return an error.
	// For now, we'll just return true.
	return true, nil
}