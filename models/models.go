package models

import (
    "time"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
    ID           primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
    Username     string               `bson:"username" json:"username"`
    PasswordHash string               `bson:"password_hash" json:"password_hash"`
    Email        string               `bson:"email" json:"email"`
    Points       int                  `bson:"points" json:"points"`
    LevelID      primitive.ObjectID   `bson:"level_id" json:"level_id"`
    GroupIDs     []primitive.ObjectID `bson:"group_ids" json:"group_ids"` // Updated Field
    Streak       int                  `bson:"streak" json:"streak"`
}

type Group struct {
    ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
    Name      string               `bson:"name" json:"name"`
    Members   []primitive.ObjectID `bson:"members" json:"members"`
    LevelID   primitive.ObjectID   `bson:"level_id" json:"level_id"`
}

type Habit struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID             primitive.ObjectID `bson:"user_id" json:"user_id"`
	GroupID            primitive.ObjectID `bson:"group_id,omitempty" json:"group_id"`
	Name               string             `bson:"name" json:"name"`
	Description        string             `bson:"description" json:"description"`
	Frequency          int                `bson:"frequency" json:"frequency"` 
	ReminderFrequency  string             `bson:"reminder_frequency,omitempty" json:"reminder_frequency"`
	ReminderStartDate  time.Time          `bson:"reminder_start_date,omitempty" json:"reminder_start_date"`
}

type Goal struct {
    ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    UserID      primitive.ObjectID `bson:"user_id" json:"user_id"`
    GroupID     primitive.ObjectID `bson:"group_id,omitempty" json:"group_id"` 
    HabitID     primitive.ObjectID `bson:"habit_id" json:"habit_id"`
    Target      int                `bson:"target" json:"target"`
}

type Reward struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
    GroupID   primitive.ObjectID `bson:"group_id,omitempty" json:"group_id"`
    Points    int                `bson:"points" json:"points"`
    LevelID   primitive.ObjectID `bson:"level_id" json:"level_id"`
}

type Level struct {
    ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name          string             `bson:"name" json:"name"`
    MinimumPoints int                `bson:"minimum_points" json:"minimum_points"`
    MaximumPoints int                `bson:"maximum_points" json:"maximum_points"`
}

type GroupLevel struct {
    ID            primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name          string             `bson:"name" json:"name"`
    MinimumPoints int                `bson:"minimum_points" json:"minimum_points"`
    MaximumPoints int                `bson:"maximum_points" json:"maximum_points"`
}

type RefreshToken struct {
    ID     primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    UserID primitive.ObjectID `bson:"user_id" json:"user_id"`
    Token  string             `bson:"token" json:"token"`
    Expiry time.Time          `bson:"expiry" json:"expiry"`
}