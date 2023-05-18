package storage

import (
	"context"
	"log"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"os"
	"testing"
	"time"
	"github.com/jghoshh/virtuo/models"
	"github.com/joho/godotenv"
)

// Test variables
var (
	testUsername1 = "testuser1"
	testEmail1    = "testuser1@example.com"
	testPassword1 = "Test1234"

	testUsername2 = "testuser2"
	testEmail2    = "testuser2@example.com"
	testPassword2 = "Test5678"

	habitName          = "TestHabit"
	habitDescription   = "This is a test habit"
	habitFrequency     = 5
	habitReminderFreq  = "daily"
	habitReminderStart = time.Now()

	testUser1ID primitive.ObjectID
	testUser2ID primitive.ObjectID

	store StorageInterface
)

// TestMain is the main entry point for the tests.
// It loads environment variables, initializes storage, and runs cleanup after tests.
func TestMain(m *testing.M) {

	err := godotenv.Load("../../.env")
	if err != nil {
		panic("Error loading .env file")
	}

	mongodbURI := os.Getenv("MONGODB_URI")
	dbName := os.Getenv("TEST_DB_NAME")
	store, err = NewStorage(dbName, mongodbURI)

	if err != nil {
		panic("Error initializing storage: " + err.Error())
	}

	testUser1 := &models.User{
		Username:     testUsername1,
		Email:        testEmail1,
		PasswordHash: testPassword1,
	}

	testUser1, err = store.AddUser(context.Background(), testUser1)
	if err != nil {
		log.Fatalf("Failed to add test user 1: %v", err)
	}

	testUser1ID = testUser1.ID

	testUser2 := &models.User{
		Username:     testUsername2,
		Email:        testEmail2,
		PasswordHash: testPassword2,
	}

	testUser2, err = store.AddUser(context.Background(), testUser2)
	if err != nil {
		log.Fatalf("Failed to add test user 2: %v", err)
	}

	testUser2ID = testUser2.ID

	code := m.Run()

	cleanup()

	os.Exit(code)
}

// cleanup deletes test habits and users after each test.
func cleanup() {
	// Delete test habits here
	_, err := store.DeleteUser(context.Background(), bson.M{"_id": testUser1ID})
	if err != nil {
		log.Printf("Failed to delete test user 1: %v", err)
	}
	_, err = store.DeleteUser(context.Background(), bson.M{"_id": testUser2ID})
	if err != nil {
		log.Printf("Failed to delete test user 2: %v", err)
	}
}

func TestAddHabit(t *testing.T) {
	habit := &models.Habit{
		Name:              habitName,
		Description:       habitDescription,
		Frequency:         habitFrequency,
		ReminderFrequency: habitReminderFreq,
		ReminderStartDate: habitReminderStart,
		UserID:            testUser1ID,
	}

	// Add habit for testUser1
	addedHabit, err := store.AddHabit(context.Background(), habit)
	if err != nil {
		t.Fatalf("Failed to add habit: %v", err)
	}

	// Make sure the ID is updated after the habit is added
	assert.NotEqual(t, primitive.NilObjectID, addedHabit.ID)

	// Retrieve the habit from the database and compare
	retrievedHabit, err := store.FindHabitsByParameter(context.Background(), bson.M{"_id": addedHabit.ID})
	if err != nil {
		t.Fatalf("Failed to retrieve habit: %v", err)
	}

	// There should be exactly one habit retrieved
	assert.Equal(t, 1, len(retrievedHabit))

	// Compare time separately with precision, reset time in the structs to a zero value
	// Let's say the precision is till seconds
	addedHabit.ReminderStartDate = addedHabit.ReminderStartDate.Truncate(time.Second)
	retrievedHabit[0].ReminderStartDate = retrievedHabit[0].ReminderStartDate.Truncate(time.Second)

	assert.True(t, addedHabit.ReminderStartDate.Equal(retrievedHabit[0].ReminderStartDate))
	addedHabit.ReminderStartDate = time.Time{}
	retrievedHabit[0].ReminderStartDate = time.Time{}

	// Compare the rest of the fields
	assert.Equal(t, *addedHabit, retrievedHabit[0])

	// Test adding a habit with missing fields
	badHabit := &models.Habit{
		Name: habitName,
	}
	_, err = store.AddHabit(context.Background(), badHabit)
	assert.Error(t, err, "Should return an error for missing fields")
}

func TestFindHabitsByParameter(t *testing.T) {
	// Find habits for testUser1
	habits, err := store.FindHabitsByParameter(context.Background(), bson.M{"user_id": testUser1ID})
	if err != nil {
		t.Fatalf("Failed to find habits: %v", err)
	}

	// Make sure the habit is found
	assert.NotEqual(t, 0, len(habits))

	// Test finding habits with a non-existent user
	habits, err = store.FindHabitsByParameter(context.Background(), bson.M{"user_id": primitive.NewObjectID()})
	assert.NoError(t, err, "Should not return an error for non-existent user")
	assert.Equal(t, 0, len(habits), "Should return no habits for non-existent user")
}

func TestUpdateHabit(t *testing.T) {
    // Find habits for testUser1
    habits, err := store.FindHabitsByParameter(context.Background(), bson.M{"user_id": testUser1ID})
    if err != nil || len(habits) == 0 {
        t.Fatalf("Failed to find habits: %v", err)
    }

    habit := habits[0]

    // Update the frequency of the first habit
    update := bson.M{
        "$set": bson.M{
            "frequency": 10,
        },
    }
    result, err := store.UpdateHabit(context.Background(), bson.M{"_id": habit.ID}, update)
    if err != nil {
        t.Fatalf("Failed to update habit: %v", err)
    }

    // Make sure the habit is updated
    assert.Equal(t, int64(1), result.ModifiedCount)

    // Verify the habit was actually updated in the database
    updatedHabit, err := store.FindHabitsByParameter(context.Background(), bson.M{"_id": habit.ID})
    if err != nil {
        t.Fatalf("Failed to retrieve habit: %v", err)
    }
    assert.Equal(t, 1, len(updatedHabit))
    assert.Equal(t, 10, updatedHabit[0].Frequency)

    // Test updating a non-existent habit
    _, err = store.UpdateHabit(context.Background(), bson.M{"_id": primitive.NewObjectID()}, update)
    if err == nil {
        t.Fatalf("Expected error when updating non-existent habit, got nil")
    }

    // Test updating with a nil filter
    _, err = store.UpdateHabit(context.Background(), nil, bson.M{"$set": bson.M{"name": "New Name"}})
    assert.Error(t, err, "Should return an error when updating with a nil filter")

    // Test updating with an empty filter
    _, err = store.UpdateHabit(context.Background(), bson.M{}, bson.M{"$set": bson.M{"name": "New Name"}})
    assert.Error(t, err, "Should return an error when updating with an empty filter")

    // Test updating with invalid update data
    _, err = store.UpdateHabit(context.Background(), bson.M{"_id": habit.ID}, "Invalid update data")
    assert.Error(t, err, "Should return an error when updating with invalid update data")

    // Test updating with invalid habit fields
    _, err = store.UpdateHabit(context.Background(), bson.M{"_id": habit.ID}, bson.M{"$set": bson.M{"name": "a", "description": "b", "frequency": 0}})
    assert.Error(t, err, "Should return an error when updating with invalid habit fields")
}

func TestDeleteHabit(t *testing.T) {
	// Find habits for testUser1
	habits, err := store.FindHabitsByParameter(context.Background(), bson.M{"user_id": testUser1ID})
	if err != nil || len(habits) == 0 {
		t.Fatalf("Failed to find habits: %v", err)
	}

	habit := habits[0]

	// Delete the first habit
	result, err := store.DeleteHabit(context.Background(), bson.M{"_id": habit.ID})
	if err != nil {
		t.Fatalf("Failed to delete habit: %v", err)
	}

	// Make sure the habit is deleted
	assert.Equal(t, int64(1), result.DeletedCount)

	// Verify the habit was actually deleted from the database
	deletedHabit, err := store.FindHabitsByParameter(context.Background(), bson.M{"_id": habit.ID})
	if err != nil {
		t.Fatalf("Failed to retrieve habit: %v", err)
	}
	assert.Equal(t, 0, len(deletedHabit))

	// Test deleting a non-existent habit
	_, err = store.DeleteHabit(context.Background(), bson.M{"_id": primitive.NewObjectID()})
	assert.NoError(t, err, "Should not return an error for non-existent habit")
}

func TestDeleteUserDeletesHabits(t *testing.T) {
	// Add a habit for testUser1
	habit := &models.Habit{
		Name:              habitName,
		Description:       habitDescription,
		Frequency:         habitFrequency,
		ReminderFrequency: habitReminderFreq,
		ReminderStartDate: habitReminderStart,
		UserID:            testUser1ID,
	}

	_, err := store.AddHabit(context.Background(), habit)
	if err != nil {
		t.Fatalf("Failed to add habit: %v", err)
	}

	// Delete testUser1
	_, err = store.DeleteUser(context.Background(), bson.M{"_id": testUser1ID})
	if err != nil {
		t.Fatalf("Failed to delete test user 1: %v", err)
	}

	// Check if all habits of testUser1 are deleted
	habits, err := store.FindHabitsByParameter(context.Background(), bson.M{"user_id": testUser1ID})
	if err != nil {
		t.Fatalf("Failed to retrieve habits: %v", err)
	}
	assert.Equal(t, 0, len(habits), "Deleting a user should delete all their habits")
}

// TestAddHabitDuplicate: Test for adding a habit with the same name for the same user.
func TestAddHabitDuplicate(t *testing.T) {
	habit := &models.Habit{
		Name:              habitName,
		Description:       habitDescription,
		Frequency:         habitFrequency,
		ReminderFrequency: habitReminderFreq,
		ReminderStartDate: habitReminderStart,
		UserID:            testUser2ID,
	}

	// Add the habit for the first time
	_, err := store.AddHabit(context.Background(), habit)
	assert.NoError(t, err, "Failed to add habit for the first time")

	// Try to add the same habit again
	_, err = store.AddHabit(context.Background(), habit)
	assert.Error(t, err, "Should return an error when trying to add a duplicate habit")
}

// TestAddHabitNonExistingUser: Test for adding a habit with a non-existing user.
func TestAddHabitNonExistingUser(t *testing.T) {
	habit := &models.Habit{
		Name:              habitName,
		Description:       habitDescription,
		Frequency:         habitFrequency,
		ReminderFrequency: habitReminderFreq,
		ReminderStartDate: habitReminderStart,
		UserID:            primitive.NewObjectID(), // non-existing user ID
	}

	_, err := store.AddHabit(context.Background(), habit)
	assert.Error(t, err, "Should return an error when trying to add a habit for a non-existing user")
}

// TestFindHabitsByInvalidParameter: Test for finding habits with an invalid parameter.
func TestFindHabitsByInvalidParameter(t *testing.T) {
    // Define a filter with an invalid parameter
    filter := bson.M{"invalid_parameter": "value"}

    // Try to find habits with the invalid parameter
    habits, err := store.FindHabitsByParameter(context.Background(), filter)

    // Assert that an error is returned
    assert.Error(t, err, "Should return an error when trying to find habits with an invalid parameter")

    // Assert that no habits are returned
    assert.Nil(t, habits, "Should return nil when trying to find habits with an invalid parameter")
}

// TestUpdateHabitInvalidData: Test for updating a habit with invalid data.
func TestUpdateHabitInvalidData(t *testing.T) {
	habits, err := store.FindHabitsByParameter(context.Background(), bson.M{"user_id": testUser2ID})
	if err != nil || len(habits) == 0 {
		t.Fatalf("Failed to find habits: %v", err)
	}

	habit := habits[0]

	// Try to update the habit with invalid data
	update := bson.M{
		"$set": bson.M{
			"frequency": -5, // negative frequency
		},
	}

	_, err = store.UpdateHabit(context.Background(), bson.M{"_id": habit.ID}, update)
	assert.Error(t, err, "Should return an error when trying to update a habit with invalid data")
}

// TestAddHabitInvalidData: Test for adding a habit with invalid data.
func TestAddHabitInvalidData(t *testing.T) {
	habit := &models.Habit{
		Name:              habitName,
		Description:       habitDescription,
		Frequency:         -1, // Negative frequency, which is invalid
		ReminderFrequency: habitReminderFreq,
		ReminderStartDate: habitReminderStart,
		UserID:            testUser1ID,
	}

	_, err := store.AddHabit(context.Background(), habit)
	assert.Error(t, err, "Should return an error when trying to add a habit with invalid data")
}