package storage

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/jghoshh/virtuo/backend/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
	"errors"
)

// MongoStorage is a struct representing a MongoDB storage. 
// It provides an interface to perform CRUD operations on various collections in the MongoDB database.
type MongoStorage struct {
	client *mongo.Client
	dbName string
}

// NewMongoStorage creates a new instance of MongoStorage.
// This function doesn't establish a connection to the MongoDB server.
// To connect to the server, use the Connect method of the returned MongoStorage instance.
func NewMongoStorage() *MongoStorage {
	return &MongoStorage{}
}

// Connect establishes a connection to the MongoDB server at the given URI abd a database name.
// Sets up indexes and unique constraints as necessary.
// Returns an error if any issues are encountered.
func (m *MongoStorage) Connect(dbName, uri string) error {

	// Set a timeout for the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create the client options for the connection
	clientOptions := options.Client().ApplyURI(uri)
	// Connect to the MongoDB server
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("error connecting to MongoDB: %v", err)
	}

	// Save the client in the MongoStorage structure
	// Save the database name that we are connecting to
	m.client = client
	m.dbName = dbName

	// Initializing users collection
	usersCollection := m.client.Database(m.dbName).Collection("users")

	// Create an index on the "email" field. This is to ensure that every user has a unique email.
	// It will also speed up queries on the "email" field
	emailIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"email": 1, // 1 for ascending order
		},
		Options: options.Index().SetUnique(true),
	}

	// Create the email index
	_, err = usersCollection.Indexes().CreateOne(ctx, emailIndexModel)
	if err != nil {
		return fmt.Errorf("error creating email index: %v", err)
	}

	// Create an index on the "username" field. This is to ensure that every user has a unique username.
	// It will also speed up queries on the "username" field
	usernameIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"username": 1,
		},
		Options: options.Index().SetUnique(true),
	}

	// Create the username index
	_, err = usersCollection.Indexes().CreateOne(ctx, usernameIndexModel)
	if err != nil {
		return fmt.Errorf("error creating username index: %v", err)
	}

	// Initializing habits collection
	habitsCollection := m.client.Database(m.dbName).Collection("habits")

	// Create an index on the "user_id" field. This will speed up queries on the "user_id" field
	userIdIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"user_id": 1, // 1 for ascending order
		},
		Options: options.Index(),
	}

	// Create the user_id index
	_, err = habitsCollection.Indexes().CreateOne(ctx, userIdIndexModel)
	if err != nil {
		return fmt.Errorf("error creating user_id index: %v", err)
	}

	// Create a compound index on the "user_id" and "name" fields.
	// This will ensure that a user can't have two habits with the same name.
	userIdNameIndexModel := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1}, // 1 for ascending order
			{Key: "name", Value: 1},    // 1 for ascending order
		},
		Options: options.Index().SetUnique(true),
	}

	// Create the user_id and name index
	_, err = habitsCollection.Indexes().CreateOne(ctx, userIdNameIndexModel)
	if err != nil {
		return fmt.Errorf("error creating user_id and name index: %v", err)
	}

	// Create an index on the "group_id" field. This will speed up queries on the "group_id" field
	groupIdIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"group_id": 1,
		},
		Options: options.Index(),
	}

	// Create the group_id index
	_, err = habitsCollection.Indexes().CreateOne(ctx, groupIdIndexModel)
	if err != nil {
		return fmt.Errorf("error creating group_id index: %v", err)
	}

	// Initializing goals collection
	goalsCollection := m.client.Database(m.dbName).Collection("goals")

	// Create an index on the "user_id", "group_id" and "habit_id" fields.
	userIdGroupIdHabitIdIndexModel := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "group_id", Value: 1},
			{Key: "habit_id", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	}	

	// Create the user_id, group_id and habit_id index
	_, err = goalsCollection.Indexes().CreateOne(ctx, userIdGroupIdHabitIdIndexModel)
	if err != nil {
		return fmt.Errorf("error creating user_id, group_id and habit_id index on goals: %v", err)
	}

	// Initializing rewards collection
	rewardsCollection := m.client.Database(m.dbName).Collection("rewards")

	// Create an index on the "user_id", "group_id" and "level_id" fields.
	userIdGroupIdLevelIdIndexModel := mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
			{Key: "group_id", Value: 1},
			{Key: "level_id", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	}

	// Create the user_id, group_id and level_id index
	_, err = rewardsCollection.Indexes().CreateOne(ctx, userIdGroupIdLevelIdIndexModel)
	if err != nil {
		return fmt.Errorf("error creating user_id, group_id and level_id index on rewards: %v", err)
	}

	// Initializing levels collection
	levelsCollection := m.client.Database(m.dbName).Collection("levels")

	// Create an index on the "name" field. This is to ensure that every level has a unique name.
	// It will also speed up queries on the "name" field
	levelNameIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"name": 1, // 1 for ascending order
		},
		Options: options.Index().SetUnique(true),
	}

	// Create the level name index
	_, err = levelsCollection.Indexes().CreateOne(ctx, levelNameIndexModel)
	if err != nil {
		return fmt.Errorf("error creating level name index: %v", err)
	}

	// Initializing groupLevels collection
	groupLevelsCollection := m.client.Database(m.dbName).Collection("groupLevels")

	// Create an index on the "name" field. This is to ensure that every group level has a unique name.
	// It will also speed up queries on the "name" field
	groupLevelNameIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"name": 1, // 1 for ascending order
		},
		Options: options.Index().SetUnique(true),
	}

	// Create the group level name index
	_, err = groupLevelsCollection.Indexes().CreateOne(ctx, groupLevelNameIndexModel)
	if err != nil {
		return fmt.Errorf("error creating group level name index: %v", err)
	}

	// Initializing refresh tokens collection
	refreshTokensCollection := m.client.Database(m.dbName).Collection("refreshTokens")

	// Create the user_id index using the model defined previously
	_, err = refreshTokensCollection.Indexes().CreateOne(ctx, userIdIndexModel)
	if err != nil {
		return fmt.Errorf("error creating user_id index: %v", err)
	}

	// Create an index on the "token" field. This will speed up queries on the "token" field
	tokenIndexModel := mongo.IndexModel{
		Keys: bson.M{
			"token": 1, // 1 for ascending order
		},
		Options: options.Index(),
	}

	// Create the token index
	_, err = refreshTokensCollection.Indexes().CreateOne(ctx, tokenIndexModel)
	if err != nil {
		return fmt.Errorf("error creating token index: %v", err)
	}

	// Initializing confirmations collection
	confirmationsCollection := m.client.Database(m.dbName).Collection("confirmations")

	// Create the user_id index
	_, err = confirmationsCollection.Indexes().CreateOne(ctx, userIdIndexModel)
	if err != nil {
		return fmt.Errorf("error creating user_id index: %v", err)
	}

	return nil
}

// Disconnect closes the connection to the MongoDB server.
// It should be called when the MongoStorage instance is no longer needed.
// Returns an error if the disconnection process fails.
func (m *MongoStorage) Disconnect() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := m.client.Disconnect(ctx)
	if err != nil {
		return fmt.Errorf("error disconnecting from MongoDB: %v", err)
	}

	return nil
}

// UserCount returns the number of documents in the 'users' collection that match the given filter.
// Returns an error if the count operation fails.
func (m *MongoStorage) UserCount(ctx context.Context, filter interface{}) (int64, error) {
	collection := m.client.Database(m.dbName).Collection("users")
	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// AddUser adds a new user document to the 'users' collection.
// The user is provided as a pointer to a User instance.
// Returns the added user instance and an error if the insert operation fails.
func (m *MongoStorage) AddUser(ctx context.Context, user *models.User) (*models.User, error) {
	collection := m.client.Database(m.dbName).Collection("users")
	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	return user, nil
}

// FindUser finds a user document in the 'users' collection that matches the given filter.
// Returns the found user as a User instance and an error if the find operation fails.
func (m *MongoStorage) FindUser(ctx context.Context, filter interface{}) (*models.User, error) {
	collection := m.client.Database(m.dbName).Collection("users")
	result := collection.FindOne(ctx, filter)
	user := &models.User{}
	err := result.Decode(user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUser updates a user document in the 'users' collection that matches the given filter with the provided update.
// Returns the updated user as a User instance and an error if the update operation fails.
func (m *MongoStorage) UpdateUser(ctx context.Context, filter interface{}, update interface{}) (*models.User, error) {
	collection := m.client.Database(m.dbName).Collection("users")
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

// DeleteUser deletes a user document from the 'users' collection that matches the given filter.
// It also deletes all associated documents from 'habits', 'goals', and 'rewards' collections and removes the user from any groups.
// Returns the result of the delete operation as a DeleteResult instance and an error if the delete operation fails.
func (m *MongoStorage) DeleteUser(ctx context.Context, filter interface{}) (*DeleteResult, error) {
	collection := m.client.Database(m.dbName).Collection("users")
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
	_, err := m.client.Database(m.dbName).Collection("habits").DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}
	_, err = m.client.Database(m.dbName).Collection("goals").DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}
	_, err = m.client.Database(m.dbName).Collection("rewards").DeleteMany(ctx, bson.M{"user_id": user.ID})
	if err != nil {
		return nil, err
	}

	// Remove user from any groups they are a part of
	for _, groupID := range user.GroupIDs {
		groupCollection := m.client.Database(m.dbName).Collection("groups")
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

// AddHabit adds a new habit document to the 'habits' collection.
// The habit is provided as a pointer to a Habit instance.
// Returns the added habit instance and an error if the insert operation fails.
func (m *MongoStorage) AddHabit(ctx context.Context, habit *models.Habit) (*models.Habit, error) {
	// Check if the habit has necessary fields
	if len(habit.Name) < 3 || len(habit.Description) < 5 || habit.Frequency <= 0 || habit.ReminderFrequency == "" || habit.ReminderStartDate.IsZero() || (habit.UserID.IsZero() && habit.GroupID.IsZero()) || (!habit.UserID.IsZero() && !habit.GroupID.IsZero()) {
		return nil, errors.New("invalid habit fields")
	}

	// Depending on whether the habit is for a user or a group, check if the user/group exists
	var err error
	if !habit.UserID.IsZero() {
		// This habit is for a user
		usersCollection := m.client.Database(m.dbName).Collection("users")
		err = usersCollection.FindOne(ctx, bson.M{"_id": habit.UserID}).Err()
	} else {
		// This habit is for a group
		groupsCollection := m.client.Database(m.dbName).Collection("groups")
		err = groupsCollection.FindOne(ctx, bson.M{"_id": habit.GroupID}).Err()
	}
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("no user/group found with id %s", habit.UserID)
		}
		return nil, err
	}

	// If the user/group exists, proceed with adding the habit
	habitsCollection := m.client.Database(m.dbName).Collection("habits")
	result, err := habitsCollection.InsertOne(ctx, habit)
	if err != nil {
		if writeException, ok := err.(mongo.WriteException); ok {
			for _, writeError := range writeException.WriteErrors {
				if writeError.Code == 11000 {
					return nil, fmt.Errorf("a habit with the name '%s' already exists for the user/group", habit.Name)
				}
			}
		}
		return nil, err
	}
	habit.ID = result.InsertedID.(primitive.ObjectID)
	return habit, nil
}

// FindHabitsByParameter finds habit documents in the 'habits' collection that match the given filter.
// Returns the found habits as a slice of Habit instances and an error if the find operation fails.
func (m *MongoStorage) FindHabitsByParameter(ctx context.Context, filter interface{}) ([]models.Habit, error) {
	// Convert the filter to a map to validate the fields
	filterMap, ok := filter.(bson.M)
	if !ok {
		return nil, errors.New("invalid filter data")
	}

	// Define a set of valid Habit fields
	validFields := map[string]struct{}{
		"_id":                 {},
		"user_id":             {},
		"group_id":            {},
		"name":                {},
		"description":         {},
		"frequency":           {},
		"reminder_frequency":  {},
		"reminder_start_date": {},
	}

	// Validate the fields in the filter
	for field := range filterMap {
		if _, ok := validFields[field]; !ok {
			return nil, errors.New("invalid field in filter")
		}
	}

	// If the filter is valid, proceed with the find operation
	collection := m.client.Database(m.dbName).Collection("habits")
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var habits []models.Habit
	for cursor.Next(ctx) {
		var habit models.Habit
		err := cursor.Decode(&habit)
		if err != nil {
			return nil, err
		}
		habits = append(habits, habit)
	}

	return habits, nil
}

// UpdateHabit updates a habit document in the 'habits' collection that matches the given filter with the provided update.
// Filter must be non-empty for a valid updation.
// Returns the result of the update operation as an UpdateResult instance and an error if the update operation fails.
func (m *MongoStorage) UpdateHabit(ctx context.Context, filter interface{}, update interface{}) (*UpdateResult, error) {
    // Check that the filter is not nil
    if filter == nil {
        return nil, errors.New("filter cannot be nil")
    }

	// Check if the filter is empty
	filterMap, ok := filter.(bson.M)
	if !ok {
		return nil, errors.New("filter must be of type bson.M")
	}
	filterEmpty := true
	for range filterMap {
		filterEmpty = false
		break
	}
	if filterEmpty {
		return nil, errors.New("filter cannot be empty")
	}

    // Fetch the habit that matches the filter
    collection := m.client.Database(m.dbName).Collection("habits")
    var habit models.Habit
    err := collection.FindOne(ctx, filter).Decode(&habit)
    
    // Check if the habit exists
    if err == mongo.ErrNoDocuments {
        return nil, errors.New("habit does not exist")
    } else if err != nil {
        return nil, err
    }

    // Apply the updates
    updateDoc, ok := update.(bson.M)
    if !ok {
        return nil, errors.New("invalid update data")
    }
    if setFields, ok := updateDoc["$set"].(bson.M); ok {
        if name, ok := setFields["name"].(string); ok {
            habit.Name = name
        }
        if desc, ok := setFields["description"].(string); ok {
            habit.Description = desc
        }
        if freq, ok := setFields["frequency"].(int); ok {
            habit.Frequency = freq
        }
    }

    // Validate the updated habit
    if len(habit.Name) < 3 || len(habit.Description) < 5 || habit.Frequency <= 0 {
        return nil, errors.New("invalid habit fields")
    }

    // If the validation passes, perform the update in the database
    result, err := collection.UpdateOne(ctx, filter, update)
    if err != nil {
        return nil, err
    }
    return &UpdateResult{MatchedCount: result.MatchedCount, ModifiedCount: result.ModifiedCount}, nil
}

// DeleteHabit deletes habit documents from the 'habits' collection that match the given filter.
// Returns the result of the delete operation as a DeleteResult instance and an error if the delete operation fails.
func (m *MongoStorage) DeleteHabit(ctx context.Context, filter interface{}) (*DeleteResult, error) {
	collection := m.client.Database(m.dbName).Collection("habits")
	result, err := collection.DeleteMany(ctx, filter)
	if err != nil {
		return nil, err
	}
	return &DeleteResult{DeletedCount: result.DeletedCount}, nil
}

// AddConfirmation adds a new confirmation document to the 'confirmations' collection.
// The confirmation is provided as a pointer to a Confirmation instance.
// Returns the added confirmation instance and an error if the insert operation fails.
func (m *MongoStorage) AddConfirmation(ctx context.Context, confirmation *models.Confirmation) (*models.Confirmation, error) {
	collection := m.client.Database(m.dbName).Collection("confirmations")
	result, err := collection.InsertOne(ctx, confirmation)
	if err != nil {
		return nil, err
	}

	confirmation.ID = result.InsertedID.(primitive.ObjectID)
	return confirmation, nil
}

// FindConfirmation finds a confirmation document in the 'confirmations' collection that matches the given filter.
// Returns the found confirmation as a Confirmation instance and an error if the find operation fails.
func (m *MongoStorage) FindConfirmation(ctx context.Context, filter interface{}) (*models.Confirmation, error) {
	collection := m.client.Database(m.dbName).Collection("confirmations")
	result := collection.FindOne(ctx, filter)
	confirmation := &models.Confirmation{}
	err := result.Decode(confirmation)
	if err != nil {
		return nil, err
	}
	return confirmation, nil
}

// UpdateConfirmation updates a confirmation document in the 'confirmations' collection that matches the given filter with the provided update.
// Returns the result of the update operation as an UpdateResult instance and an error if the update operation fails.
func (m *MongoStorage) UpdateConfirmation(ctx context.Context, filter interface{}, update interface{}) (*UpdateResult, error) {
	collection := m.client.Database(m.dbName).Collection("confirmations")
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, errors.New("no confirmation found to update")
	}

	return &UpdateResult{MatchedCount: result.MatchedCount, ModifiedCount: result.ModifiedCount}, nil
}

// DeleteConfirmation deletes a confirmation document from the 'confirmations' collection that matches the given filter.
// Returns the result of the delete operation as a DeleteResult instance and an error if the delete operation fails.
func (m *MongoStorage) DeleteConfirmation(ctx context.Context, filter interface{}) (*DeleteResult, error) {
	collection := m.client.Database(m.dbName).Collection("confirmations")
	result, err := collection.DeleteOne(ctx, filter)
	if err != nil {
		return nil, err
	}

	return &DeleteResult{DeletedCount: result.DeletedCount}, nil
}