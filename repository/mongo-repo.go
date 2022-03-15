package repository

import (
	"context"
	"os"

	"github.com/nillga/jwt-server/entity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoRepository struct {
	mongoUri string
}

type rawUser struct {
	Id interface{} `bson:"_id"`
	Name string `bson:"name"`
	Email string `bson:"email"`
	Password []byte `bson:"password"`
}

const (
	db string = "sample_name"
	collection string = "users"
)

func NewMongoRepo() JwtRepository {
	return &mongoRepository{
		mongoUri: os.Getenv("MONGODB_URI"),
	}
}

func (m *mongoRepository) Store(user *entity.User) (*entity.User, error) {
	ctx := context.Background()
	client, err := mongo.Connect(ctx,options.Client().ApplyURI(m.mongoUri))
	if err != nil {
		return nil, err
	}
	users := client.Database(db).Collection(collection)
	
	defer client.Disconnect(ctx)

	doc := bson.D{
		primitive.E{
			Key: "name", 
			Value: user.Username,
		},
		primitive.E{
			Key: "email", 
			Value: user.Email,
		},
		primitive.E{
			Key: "password", 
			Value: user.Password,
		},
	}

	inserted, err := users.InsertOne(ctx, doc)
	if err != nil {
		return nil, err
	}

	created := &entity.User{
		Id: inserted.InsertedID.(primitive.ObjectID).Hex(),
		Username: user.Username,
	}

	return created, nil
}

func (m *mongoRepository) Find(user *entity.User) (*entity.User, error) {
	ctx := context.Background()
	client, err := mongo.Connect(ctx,options.Client().ApplyURI(m.mongoUri))
	if err != nil {
		return nil, err
	}
	users := client.Database(db).Collection(collection)
	
	defer client.Disconnect(ctx)
	var result rawUser
	query := bson.D{
		primitive.E{
			Key: "$or", 
			Value: bson.A{
				bson.D{
					primitive.E{
						Key: "_id", 
						Value: user.Id,
					},
				},
				bson.D{
					primitive.E{
						Key: "name", 
						Value: user.Username,
					},
				},
				bson.D{
					primitive.E{
						Key: "email", 
						Value: user.Email,
					},
				},
			},
		},
	}
	
	if err := users.FindOne(ctx, query).Decode(&result); err != nil {
		return nil, err
	}

	return result.ToUser(), nil
}

func (m *mongoRepository) FindById(id string) (*entity.User, error) {
	ctx := context.Background()
	client, err := mongo.Connect(ctx,options.Client().ApplyURI(m.mongoUri))
	if err != nil {
		return nil, err
	}
	users := client.Database(db).Collection(collection)
	
	defer client.Disconnect(ctx)
	var raw rawUser
	bsonId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.D{
		primitive.E{
			Key: "$and", 
			Value: bson.A{
				bson.D{
					primitive.E{
						Key: "_id", 
						Value: bsonId,
					},
				},
			},
		},
	}
	
	if err := users.FindOne(ctx, query).Decode(&raw); err != nil {
		return nil, err
	}

	return raw.ToUser(), nil
}

func (m *mongoRepository) Delete(id string) error {
	ctx := context.Background()
	client, err := mongo.Connect(ctx,options.Client().ApplyURI(m.mongoUri))
	if err != nil {
		return err
	}
	users := client.Database(db).Collection(collection)
	
	defer client.Disconnect(ctx)
	bsonId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}
	query := bson.D{
		primitive.E{
			Key: "$and", 
			Value: bson.A{
				bson.D{
					primitive.E{
						Key: "_id", 
						Value: bsonId,
					},
				},
			},
		},
	}
	
	if _, err := users.DeleteOne(ctx, query); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil
		}
		return err
	}

	return nil
}

func (m *mongoRepository) UpdateUser(id string, user *entity.User) error {
	ctx := context.Background()
	client, err := mongo.Connect(ctx,options.Client().ApplyURI(m.mongoUri))
	if err != nil {
		return err
	}
	users := client.Database(db).Collection(collection)

	defer client.Disconnect(ctx)
	bsonId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.D{
		primitive.E{
			Key: "$set",
			Value: bson.D{
				primitive.E{
					Key: "name",
					Value: user.Username,
				},
				primitive.E{
					Key: "email",
					Value: user.Email,
				},
				primitive.E{
					Key: "password",
					Value: user.Password,
				},
			},
		},
	}

	if _, err = users.UpdateByID(ctx, bsonId, update); err != nil {
		return err
	}

	return nil
}

func (r *rawUser) ToUser() *entity.User {
	return &entity.User{
		Id: r.Id.(primitive.ObjectID).Hex(),
		Username: r.Name,
		Email: r.Email,
		Password: r.Password,
	}
}