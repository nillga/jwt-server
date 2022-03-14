package repository

import (
	"context"
	"database/sql"
	"github.com/nillga/jwt-server/entity"
	"github.com/nillga/jwt-server/postgresql"
	"github.com/rubenv/sql-migrate"
	"strconv"
)

type postgresRepo struct {
	postgresUri string
}

var migrations = &migrate.FileMigrationSource{
	Dir: "sql/schema",
}

var initialized = false

func NewPostgresRepo(postgresUri string) JwtRepository {
	if !initialized {
		db, err := sql.Open("postgres", postgresUri)
		defer db.Close()
		if err != nil {
			panic(err)
		}
		if _, err = migrate.Exec(db, "postgres", migrations, migrate.Up); err != nil {
			panic(err)
		}
		initialized = true
	}

	return &postgresRepo{
		postgresUri: postgresUri,
	}
}

func (p *postgresRepo) Store(user *entity.User) (*entity.User, error) {
	db, err := sql.Open("postgres", p.postgresUri)
	if err != nil {
		return nil, err
	}

	defer db.Close()
	ctx := context.Background()
	row, err := postgresql.New(db).CreateUser(ctx, postgresql.CreateUserParams{
		Name:     user.Username,
		Mail:     user.Email,
		Password: string(user.Password),
	})
	if err != nil {
		return nil, err
	}
	return &entity.User{
		Id:       strconv.FormatInt(row.ID, 10),
		Username: row.Name,
		Email:    row.Mail,
		Password: []byte(row.Password),
	}, nil
}

func (p *postgresRepo) Find(user *entity.User) (*entity.User, error) {
	db, err := sql.Open("postgres", p.postgresUri)
	if err != nil {
		return nil, err
	}

	defer db.Close()
	ctx := context.Background()

	row, err := postgresql.New(db).FindUser(ctx, postgresql.FindUserParams{
		Name: user.Username,
		Mail: user.Email,
	})
	if err != nil {
		return nil, err
	}
	return &entity.User{
		Id:       strconv.FormatInt(row.ID, 10),
		Username: row.Name,
		Email:    row.Mail,
		Password: []byte(row.Password),
	}, nil
}

func (p *postgresRepo) FindById(id string) (*entity.User, error) {
	db, err := sql.Open("postgres", p.postgresUri)
	if err != nil {
		return nil, err
	}

	defer db.Close()
	ctx := context.Background()

	intId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, err
	}

	row, err := postgresql.New(db).FindUserById(ctx, intId)
	if err != nil {
		return nil, err
	}
	return &entity.User{
		Id:       strconv.FormatInt(row.ID, 10),
		Username: row.Name,
		Email:    row.Mail,
		Password: []byte(row.Password),
	}, nil
}

func (p *postgresRepo) Delete(id string) error {
	db, err := sql.Open("postgres", p.postgresUri)
	if err != nil {
		return err
	}

	defer db.Close()
	ctx := context.Background()

	intId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	return postgresql.New(db).DeleteUser(ctx, intId)
}

func (p *postgresRepo) UpdateUser(id string, user *entity.User) error {
	db, err := sql.Open("postgres", p.postgresUri)
	if err != nil {
		return err
	}

	defer db.Close()
	ctx := context.Background()

	intId, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return err
	}

	return postgresql.New(db).UpdateUser(ctx, postgresql.UpdateUserParams{
		ID:       intId,
		Password: string(user.Password),
	})
}