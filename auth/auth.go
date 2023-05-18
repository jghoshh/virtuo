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
	"github.com/jghoshh/virtuo/storage"
	"github.com/jghoshh/virtuo/models"
	"github.com/jghoshh/virtuo/utils"
)

var store storage.StorageInterface
var jwtSigningKey string
var KeyringKey string
const KeyringService = "Virtuo"

// InitAuth initializes the global storage and jwtSigningKey variables.
// It is required to be called before any other function in this package.
// It takes a MongoDB URI, signing key, and auth token as input.
func InitAuth(dbName, mongodbURI, signingKey string) {
	var err error
	jwtSigningKey = signingKey
	store, err = storage.NewStorage(dbName, mongodbURI)
	if err != nil {
		panic("Error initializing storage: " + err.Error())
	}
}

// SignIn logs in a user with the username and password. Returns an error if the username or password is incorrect.
func SignIn(username string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", fmt.Errorf("invalid username")
	}
	
	if !utils.ValidatePassword(password) {
		return "", "", fmt.Errorf("password must be at least 8 characters and contain both letters and numbers")
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
func SignUp(username string, email string, password string) (string, string, error) {

	if len(username) < 2 {
		return "", "", fmt.Errorf("username must be at least 2 characters")
	}

	if !utils.ValidateEmail(email) {
		return "", "", fmt.Errorf("invalid email format")
	}

	if !utils.ValidatePassword(password) {
		return "", "", fmt.Errorf("password must be at least 8 characters and contain both letters and numbers")
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

	token, refreshToken, err := CreateTokens(newUserID.Hex()) 
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
func UpdateUser(userId, currentPassword, newUsername, newEmail, newPassword string) (bool, error) {

	foundUser, err := store.FindUser(context.Background(), bson.M{"_id": userId})
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
		update["$set"].(bson.M)["username"] = newUsername
	}

	if newEmail != "" {
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

	_, err = store.UpdateUser(context.Background(), bson.M{"_id": userId}, update)
	if err != nil {
		return false, errors.New("error updating user credentials")
	}

	return true, nil
}

// DeleteUser deletes the user with the given id.
func DeleteUser(userId string) (bool, error) {

	_, err := store.DeleteUser(context.Background(), bson.M{"_id": userId})

	if err != nil {
		return false, fmt.Errorf("error deleting user: %v", err)
	}
	
	return true, nil
}