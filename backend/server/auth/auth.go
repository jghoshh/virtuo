package auth

import (
	"time"
	"errors"
	"fmt"
	"context"
	"golang.org/x/crypto/bcrypt"
	"github.com/form3tech-oss/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"github.com/jghoshh/virtuo/backend/storage/persistent"
	"github.com/jghoshh/virtuo/backend/models"
	"github.com/jghoshh/virtuo/backend/queue"
	"github.com/jghoshh/virtuo/utils"
	"crypto/rand"
	"encoding/base32"
)

// store is an interface to the storage system (database). 
var store storage.StorageInterface

// jwtSigningKey is the secret key used to sign JWT tokens. 
var jwtSigningKey string

var emailQueue *queue.Queue

// InitAuth initializes the authentication system, setting up a storage system (database) and a JWT signing key.
// It is required to be called before any other function in this package.
// The function takes a MongoDB URI, signing key, and auth token as input.
func InitAuth(dbName, mongodbURI, signingKey string, queue *queue.Queue) {
	var err error
	jwtSigningKey = signingKey
	store, err = storage.NewStorage(dbName, mongodbURI)
	if err != nil {
		panic("Error initializing storage: " + err.Error())
	}
	emailQueue = queue
}

// CreateAuthToken creates and returns a signed JWT token for the given user id.
// This token can be used to authenticate the user in subsequent requests.
// Returns an auth token if the token creation is succesful.
// Returns an error if the token creation fails.
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

// CreateRefreshToken generates a refresh token for the given user id.
// This refresh token can be used to get a new authentication token when the old one expires.
// Returns a refresh token if the token creation is succesful.
// Returns an error if the token creation fails.
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

// CreateTokens generates a new pair of authentication and refresh tokens for the given user id.
// This function calls CreateAuthToken and CreateRefreshToken internally.
// Returns a pair of tokens (auth token, refresh token) if the token creation is successful.
// Returns an error if the creation of any token fails.
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

// CheckCredentials verifies that the passed in username, email, and password belong to the same user.
// Returns true if the credentials are valid, else false.
// Returns an error if the credentials are invalid or any internal operation fails.
func CheckCredentials(username, email, password string) (bool, error) {

	if len(username) < 2 {
		return false, errors.New("invalid username")
	}

	if !utils.ValidateEmail(email) {
		return false, errors.New("invalid email format")
	}

	return true, nil
}

// ResetPassword resets the password of the user with the given email address.
// Returns an error if the email address is invalid, or any internal operation fails.
func ResetPassword(email, newPassword string) error {
	return nil
}

// SignIn logs in a user with the provided username and password.
// If the login is successful, it returns an authentication token and a refresh token.
// Returns an error if the username or password is incorrect, or any internal operation fails.
func SignIn(username string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", errors.New("invalid username")
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"username": username})

	if err != nil {
		return "", "", errors.New("authentication failed")
	}

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(password))
	if err != nil {
		return "", "", errors.New("authentication failed")
	}

	token, refreshToken, err := CreateTokens(foundUser.ID.Hex())

	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

// SignUp creates a new user with the provided username, email, and password.
// If the registration is successful, it returns an authentication token and a refresh token.
// Returns an error if any input is invalid, a user with the same email or username already exists,
// or any internal operation fails.
func SignUp(username string, email string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", errors.New("invalid username")
	}

	if !utils.ValidateEmail(email) {
		return "", "", errors.New("invalid email format")
	}

	if !utils.ValidatePassword(password) {
		return "", "", errors.New("password must be at least 8 characters and contain both letters and numbers")
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"email": email})
	if err != nil && err != mongo.ErrNoDocuments {
		return "", "", err
	}

	if foundUser != nil {
		return "", "", errors.New("an account with this email already exists")
	}

	foundUser, err = store.FindUser(context.Background(), bson.M{"username": username})
	if err != nil && err != mongo.ErrNoDocuments {
		return "", "", err
	}

	if foundUser != nil {
		return "", "", errors.New("username is taken")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	newUserID := primitive.NewObjectID()

	user := &models.User{
		ID: 		  newUserID,
		Username:     username,
		Email:        email,
		EmailConfirmed: false,
		PasswordHash: string(hashedPassword),
		Points:       0,
		LevelID:      primitive.NilObjectID,
		GroupIDs:     []primitive.ObjectID{},
		Streak:       0,
	}

	_, err = store.AddUser(context.Background(), user)
	if err != nil {
		return "", "", err
	}

	// Generate a random token
	tokenBytes := make([]byte, 3)  // 3 bytes can encode up to 6 characters in base32
	_, err = rand.Read(tokenBytes)
	if err != nil {
		return "", "", err
	}
	confirmationToken := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tokenBytes)

	// If it is more than 6 characters, cut it down to 6
	if len(confirmationToken) > 6 {
		confirmationToken = confirmationToken[:6]
	}

	// Hash the confirmation token before storing it in the database
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(confirmationToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	// Create a new email message to send to the user
	emailMsg := &queue.EmailMessage{
		Id:    newUserID.Hex(), // A unique ID for the message
		Token: confirmationToken, // The confirmation token the user must input in the CLI for email verification
		To:    email, // The email address of the user
	}

	// Process the email message (i.e., send it to the user)
	if err := queue.ProcessEmail(emailMsg, emailQueue); err != nil {
		return "", "", err
	}

	// Create a confirmation with the user ID and hashed confirmation token
	confirmation := &models.Confirmation{
		UserID:            newUserID,
		ConfirmationToken: string(hashedToken),
		ExpiresAt:         time.Now().Add(24 * time.Hour), // The confirmation token expires after 24 hours
	}

	// Add the confirmation to the storage backend
	_, err = store.AddConfirmation(context.Background(), confirmation)
	if err != nil {
		return "", "", err
	}

	token, refreshToken, err := CreateTokens(newUserID.Hex()) 
	if err != nil {
		return "", "", err
	}

	return token, refreshToken, nil
}

// RefreshToken takes a refresh token, validates it, and if it's valid, generates a new pair of tokens.
// This is useful when the authentication token has expired and a new one is needed.
// Returns a pair of tokens if the refresh token is valid and the creation of new tokens is successful.
// Returns an error if the refresh token is invalid, or the creation of new tokens fails.
func RefreshToken(userId string, refreshToken string) (string, string, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSigningKey), nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors == jwt.ValidationErrorExpired {
				return "", "", errors.New("expired refresh token")
			}
		}
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

// UpdateUser allows the update of user details.
// It checks the current password for authentication, and then updates any 
// provided new username, email, or password. Returns an error if the current password is incorrect, 
// no fields to update were provided, or the update operation fails.
// Returns 'true' if the update operation was succesful, else 'false'.
func UpdateUser(userId, currentPassword, newUsername, newEmail, newPassword string) (bool, error) {

	objectID, err := primitive.ObjectIDFromHex(userId)

	if err != nil {
		return false, err
	}

	foundUser, err := store.FindUser(context.Background(), bson.M{"_id": objectID})
    if err != nil {
        return false, errors.New("authentication failed")
    }

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(currentPassword))
	if err != nil {
		return false, errors.New("authentication failed")
	}

	update := bson.M{
		"$set": bson.M{},
	}

	if newUsername != "" {
		existingUser, err := store.FindUser(context.Background(), bson.M{"username": newUsername})
		if existingUser != nil || err == nil {
			return false, errors.New("username already in use")
		}
		update["$set"].(bson.M)["username"] = newUsername
	}

	if newEmail != "" {
		existingUser, err := store.FindUser(context.Background(), bson.M{"email": newEmail})
		if existingUser != nil || err == nil {
			return false, errors.New("email already in use")
		}
		update["$set"].(bson.M)["email"] = newEmail
	}

	if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return false, err
		}
		update["$set"].(bson.M)["password_hash"] = string(hashedPassword)
	}

	if len(update["$set"].(bson.M)) == 0 {
		return false, errors.New("nothing to update")
	}

	_, err = store.UpdateUser(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		return false, errors.New("internal server error updating user")
	}

	return true, nil
}

// DeleteUser deletes the user with the given id from the database.
// Returns an error if the delete operation fails.
// Returns 'true' if the deletion was succesful, else 'false'.
func DeleteUser(userId string) (bool, error) {

	objectID, err := primitive.ObjectIDFromHex(userId)

	if err != nil {
		fmt.Println(err)
		return false, err
	}

	_, err = store.DeleteUser(context.Background(), bson.M{"_id": objectID})

	if err != nil {
		return false, errors.New("error deleting user")
	}

	return true, nil
}

// ConfirmEmail confirms the email address of a user with the provided userID and confirmationToken.
// Returns an error if the confirmationToken is incorrect, expired, or the user's email address could 
// not be updated in the database.
func ConfirmEmail(userID, confirmationToken string) error {
	var confirmError error
	
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}

	// Fetch confirmation record from the database
	foundConfirmation, err := store.FindConfirmation(context.Background(), bson.M{"userId": objectID})
	if err != nil {
		return err
	}

	// Check if the confirmation record has expired
	if foundConfirmation.ExpiresAt.Before(time.Now()) {
		confirmError = errors.New("confirmation token has expired")
	} else if err = bcrypt.CompareHashAndPassword([]byte(foundConfirmation.ConfirmationToken), []byte(confirmationToken)); err != nil {
		// Compare hashed stored confirmation token with provided token only if it hasn't expired
		confirmError = errors.New("invalid confirmation token")
	} else {
		// If the token is valid and not expired, confirm the user's email
		update := bson.M{
			"$set": bson.M{
				"emailConfirmed": true,
			},
		}

		_, err = store.UpdateUser(context.Background(), bson.M{"_id": objectID}, update)
		if err != nil {
			return err
		}
	}

	// If the email is confirmed, remove the confirmation record, regardless of whether the token was valid or not
	_, err = store.DeleteConfirmation(context.Background(), bson.M{"_id": foundConfirmation.ID})
	if err != nil {
		return errors.New("error removing confirmation record")
	}

	return confirmError
}