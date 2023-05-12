package storage

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/jghoshh/virtuo/models"
	"time"
	"errors"
)

var db = "virtuo"

type MongoStorage struct {
	client *mongo.Client
}

func NewMongoStorage() *MongoStorage {
	return &MongoStorage{}
}

func (m *MongoStorage) Connect(uri string) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("error connecting to MongoDB: %v", err)
	}

	m.client = client

	collection := m.client.Database(db).Collection("users")

	// Create an index on the "email" field
	emailIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"email": 1, // 1 for ascending order
		},
		Options: options.Index().SetUnique(true),
	}

	_, err = collection.Indexes().CreateOne(ctx, emailIndexModel)
	if err != nil {
		return fmt.Errorf("error creating email index: %v", err)
	}

	// Create an index on the "username" field
	usernameIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"username": 1,
		},
		Options: options.Index().SetUnique(true),
	}

	_, err = collection.Indexes().CreateOne(ctx, usernameIndexModel)
	if err != nil {
		return fmt.Errorf("error creating username index: %v", err)
	}

	return nil
}

func (m *MongoStorage) Disconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := m.client.Disconnect(ctx)
	if err != nil {
		return fmt.Errorf("error disconnecting from MongoDB: %v", err)
	}

	return nil
}

func (m *MongoStorage) UserCount(ctx context.Context, filter interface{}) (int64, error) {
	collection := m.client.Database(db).Collection("users")
	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (m *MongoStorage) AddUser(ctx context.Context, user *models.User) (*models.User, error) {
	collection := m.client.Database(db).Collection("users")
	_, err := collection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (m *MongoStorage) FindUser(ctx context.Context, filter interface{}) (*models.User, error) {
	collection := m.client.Database(db).Collection("users")
	result := collection.FindOne(ctx, filter)
	user := &models.User{}
	err := result.Decode(user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (m *MongoStorage) UpdateUser(ctx context.Context, filter interface{}, update interface{}) (*models.User, error) {
	collection := m.client.Database(db).Collection("users")
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, errors.New("no user found to update")
	}
	updatedUser, err := m.FindUser(ctx, filter)
	if err != nil {
		return nil, err
	}
	return updatedUser, nil
}

func (m *MongoStorage) DeleteUser(ctx context.Context, filter interface{}) (*DeleteResult, error) {
	collection := m.client.Database(db).Collection("users")
	userResult := collection.FindOne(ctx, filter)
	if err := userResult.Err(); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	user := &models.User{}
	if err := userResult.Decode(user); err != nil {
		return nil, err
	}

	// Delete all habits, goals, and rewards associated with the user
	_, err := m.client.Database(db).Collection("habits").DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}
	_, err = m.client.Database(db).Collection("goals").DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}
	_, err = m.client.Database(db).Collection("rewards").DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}

	// Remove user from any groups they are a part of
	for _, groupID := range user.GroupIDs {
		groupCollection := m.client.Database(db).Collection("groups")
		_, err = groupCollection.UpdateOne(
			ctx,
			bson.M{"_id": groupID},
			bson.M{"$pull": bson.M{"members": user.ID}},
		)
		if err != nil {
			return nil, err
		}
	}

	// Finally, delete the user
	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &DeleteResult{DeletedCount: result.DeletedCount}, nil
}