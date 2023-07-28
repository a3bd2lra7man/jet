//go:build integration
// +build integration

package jwt

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var coll *mongo.Collection

func init() {
	uri := "mongodb://127.0.0.1:27017"
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	db := client.Database("test-db")
	db.Collection("jwt_tokens").Drop(context.Background())

	col = db.Collection("jwt_tokens")
	coll = db.Collection("jwt_tokens")
}

func TestSave(t *testing.T) {
	jwtCode := JwtToken{Token: "token1", Refresh: "refresh1"}

	err := save(jwtCode)

	if err != nil {
		t.Fatalf("err expected to be : %v found %v", nil, err)
	}

	var jwtTokenInDb JwtToken
	find := bson.D{{Key: "token", Value: "token1"}, {Key: "refresh", Value: "refresh1"}}

	coll.FindOne(context.Background(), find).Decode(&jwtTokenInDb)

	if jwtTokenInDb.Token != "token1" {
		t.Fatalf("expected token to be : %v found %v", "token1", jwtTokenInDb.Token)
	}
	if jwtTokenInDb.Refresh != "refresh1" {
		t.Fatalf("expected refresh to be : %v found %v", "refresh1", jwtTokenInDb.Refresh)
	}

}

func TestGet(t *testing.T) {
	jwtCode := JwtToken{Token: "token2", Refresh: "refresh2"}
	coll.InsertOne(context.Background(), bson.D{{Key: "token", Value: jwtCode.Token}, {Key: "refresh", Value: jwtCode.Refresh}})

	jwtTokenInDb, err := get(jwtCode)

	if err != nil {
		t.Fatalf("expected err to be : %v found %v", nil, err)
	}
	if jwtTokenInDb.Token != "token2" {
		t.Fatalf("expected token to be : %v found %v", "token2", jwtTokenInDb.Token)
	}
	if jwtTokenInDb.Refresh != "refresh2" {
		t.Fatalf("expected refresh to be : %v found %v", "refresh1", jwtTokenInDb.Refresh)
	}
}

func TestDelete(t *testing.T) {
	jwtCode := JwtToken{Token: "token3", Refresh: "refresh3"}
	res, _ := coll.InsertOne(context.Background(), bson.D{{Key: "token", Value: jwtCode.Token}, {Key: "refresh", Value: jwtCode.Refresh}})

	err := delete(res.InsertedID.(primitive.ObjectID).Hex())

	if err != nil {
		t.Fatalf("expected err to be : %v found %v", nil, err)
	}

	findRes := coll.FindOne(context.Background(), bson.D{{Key: "_id", Value: res.InsertedID}})

	if findRes.Err() != mongo.ErrNoDocuments {
		t.Fatalf("expected document to not be found")
	}
}
