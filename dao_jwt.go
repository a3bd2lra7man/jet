package jwt

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var col *mongo.Collection

func Setup(db *mongo.Database) {
	col = db.Collection("jwt_tokens")

	// col.Indexes().CreateOne(context.Background(), mongo.IndexModel{
	// 	Keys:    bson.D{{Key: "created_at", Value: 1}},
	// 	Options: options.Index().SetExpireAfterSeconds(int32(time.Now().Add(time.Hour).Unix())), // Will be removed after 24 Hours.
	// })
}

func save(token JwtToken) error {
	_, err := col.InsertOne(context.Background(), bson.D{{Key: "token", Value: token.Token}, {Key: "refresh", Value: token.Refresh}, {Key: "created_at", Value: time.Now().Unix()}})
	return err
}

func get(token JwtToken) (JwtToken, error) {
	err := col.FindOne(context.Background(), bson.D{{Key: "token", Value: token.Token}, {Key: "refresh", Value: token.Refresh}}).Decode(&token)

	if err != nil {
		return JwtToken{}, err
	}

	return token, nil
}

func delete(id string) error {
	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	_, err = col.DeleteOne(context.Background(), bson.D{{Key: "_id", Value: objId}})

	if err != nil {
		return err
	}

	return nil
}
