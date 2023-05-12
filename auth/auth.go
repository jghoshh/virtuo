package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/bcrypt"
	"github.com/jghoshh/virtuo/models"
	"github.com/jghoshh/virtuo/core/storage"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"regexp"
)

var store storage.StorageInterface
var jwtSigningKey string
var KeyringKey string
const KeyringService = "Virtuo"

// InitAuth initializes the global storage and jwtSigningKey variables.
// It is required to be called before any other function in this package.
// It takes a MongoDB URI, signing key, and auth token as input.
func InitAuth(mongodbURI, signingKey, authToken string) {
	var err error
	jwtSigningKey = signingKey
	KeyringKey = authToken
	store, err = storage.NewStorage(mongodbURI)
	if err != nil {
		panic("Error initializing storage: " + err.Error())
	}
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

// getUserIDFromToken extracts the user ID from the JWT token stored in the keyring and returns it as a MongoDB ObjectID.
// If the token is not found, invalid, or the user ID is invalid, it returns an error.
func getUserIDFromToken() (primitive.ObjectID, error) {
	token, err := keyring.Get(KeyringService, KeyringKey)
	if err != nil {
		return primitive.NilObjectID, errors.New("user not authenticated")
	}

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSigningKey), nil
	})

	if err != nil {
		fmt.Println("Error parsing token:", err)
		return primitive.NilObjectID, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Error casting token claims to jwt.MapClaims")
		return primitive.NilObjectID, errors.New("invalid token claims")
	}

	userIDStr, ok := claims["id"].(string)

	if !ok {
		fmt.Println("Error getting 'id' from token claims")
		return primitive.NilObjectID, errors.New("invalid token claims")
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		fmt.Println("Error converting user ID string to ObjectID:", err)
		return primitive.NilObjectID, errors.New("invalid user ID")
	}

	return userID, nil
}

// IsUserAuthenticated checks if there is a valid JWT token stored in the keyring.
// It returns true if a valid token is found, false otherwise.
// If the token is expired or invalid, it returns an error.
func IsUserAuthenticated() (bool, error) {
	tokenStr, err := keyring.Get(KeyringService, KeyringKey)
	if err != nil {
		if err == keyring.ErrNotFound {
			return false, nil
		}
		return false, err
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSigningKey), nil
	})

	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return true, nil
		}
		return false, errors.New("token is expired")
	}
	return false, errors.New("invalid token")
}

// SignUpUser creates a new user with the provided username, email, and password.
// It validates the email and password, checks if a user with the same email already exists, and saves the new user in the database.
// After successful sign up, it automatically signs in the user and returns a signed JWT token.
func SignUpUser(username, email, password string) (string, error) {
	if !(len(username) > 1) {
		return "", errors.New("username must be at least 2 characters")
	}

	if !validateEmail(email) {
		return "", errors.New("invalid email format")
	}

	if !validatePassword(password) {
		return "", errors.New("password must be at least 8 characters and contain both letters and numbers")
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"email": email})
	if err != nil && err != mongo.ErrNoDocuments {
		return "", err
	}
	if foundUser != nil {
		return "", errors.New("an account with this email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Points:       0,
		LevelID:      primitive.NilObjectID,
		GroupIDs:     []primitive.ObjectID{},
		Streak:       0,
	}

	_, err = store.AddUser(context.Background(), user)
	if err != nil {
		return "", err
	}

	signedToken, err := SignInUser(email, password)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// SignInUser authenticates a user with the provided email and password, and returns a signed JWT token.
// If a user is already signed in, it returns an error.
func SignInUser(email, password string) (string, error) {
	value, err := keyring.Get(KeyringService, KeyringKey)
	if err == nil {
		fmt.Println("Value associated with the keyring key:", value)
		return "", errors.New("user is already signed in")
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"email": email})
	if err != nil {
		return "", errors.New("authentication failed")
	}

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password))
	if err != nil {
		return "", errors.New("authentication failed")
	}

	claims := jwt.MapClaims{
		"id":  foundUser.ID.Hex(),
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := newToken.SignedString([]byte(jwtSigningKey))

	if err != nil {
		return "", err
	}

	err = keyring.Set(KeyringService, KeyringKey, signedToken)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// SignOutUser removes the JWT token stored in the keyring, effectively signing out the user.
// If no user is signed in, it returns an error.
func SignOutUser() error {
	_, err := keyring.Get(KeyringService, KeyringKey)
	if err != nil {
		if err == keyring.ErrNotFound {
			return errors.New("no user is signed in")
		}
		return errors.New("failed to access keyring")
	}

	err = keyring.Delete(KeyringService, KeyringKey)
	if err != nil {
		return errors.New("failed to sign out user")
	}

	return nil
}

// UpdateUserCredentials updates the logged-in user's username, email, and password.
// It verifies the user's current password before making any changes.
// If the new credentials are not provided, it returns an error.
func UpdateUserCredentials(loggedInEmail, currentPassword, newUsername, newEmail, newPassword string) error {
    loggedInUserID, err := getUserIDFromToken()
    if err != nil {
        return err
    }

    foundUser, err := store.FindUser(context.Background(), bson.M{"_id": loggedInUserID})
    if err != nil {
        return errors.New("authentication failed")
    }

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(currentPassword))
	if err != nil {
		return errors.New("incorrect current password")
	}

	update := bson.M{
		"$set": bson.M{},
	}

	if newUsername != "" {
		update["$set"].(bson.M)["username"] = newUsername
	}

	if newEmail != "" {
		update["$set"].(bson.M)["email"] = newEmail
	}

	if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		update["$set"].(bson.M)["password_hash"] = string(hashedPassword)
	}

	if len(update["$set"].(bson.M)) == 0 {
		return errors.New("nothing to update")
	}

	_, err = store.UpdateUser(context.Background(), bson.M{"_id": loggedInUserID}, update)
	if err != nil {
		return errors.New("error updating user credentials")
	}
	return nil
}

// DeleteUser deletes the currently logged in user from the database and signs out the user.
// If there is no user signed in, it returns an error.
func DeleteUser() error {

	loggedInUserID, err := getUserIDFromToken()

	if err != nil {
		return err
	}
	_, err = store.DeleteUser(context.Background(), bson.M{"_id": loggedInUserID})
	if err != nil {
		return fmt.Errorf("error deleting user: %v", err)
	}

	err = SignOutUser()
	if err != nil {
		return fmt.Errorf("error signing out user, but the user was deleted successfully: %v", err)
	}

	return nil
}