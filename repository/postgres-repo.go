package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"

	_ "github.com/lib/pq"
	"github.com/nillga/jwt-server/entity"
	"github.com/nillga/jwt-server/postgresql"
	migrate "github.com/rubenv/sql-migrate"
	"golang.org/x/crypto/bcrypt"
)

type postgresRepo struct {
	postgresUri string
}

var migrations = &migrate.FileMigrationSource{
	Dir: "./sql/schema",
}

var initialized = false

func NewPostgresRepo() JwtRepository {
	postgresUri := fmt.Sprintf("host=%s port=%s user=%s "+"password=%s dbname=%s sslmode=disable", os.Getenv("PG_HOST"), os.Getenv("PG_PORT"), os.Getenv("PG_USER"), os.Getenv("PG_PASS"), os.Getenv("PG_DBNAME"))

	if !initialized {
		db, err := sql.Open("postgres", postgresUri)
		defer db.Close()
		if err != nil {
			panic(err)
		}
		fmt.Println("db connect successful")
		dir, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		fmt.Println("pwd ==> " + dir)
		dirs, err := os.ReadDir(dir)
		if err != nil {
			panic(err)
		}
		for i := range dirs {
			fmt.Println("-> subdir: " + dirs[i].Name())
		}
		if _, err = migrate.Exec(db, "postgres", migrations, migrate.Up); err != nil {
			panic(err)
		}
		ctx := context.Background()
		genesisPass, err := bcrypt.GenerateFromPassword([]byte("btc"), 14)
		if err != nil {
			panic(err)
		}
		if _, err = postgresql.New(db).CreateUser(ctx, postgresql.CreateUserParams{
			Name:     "genesis_admin",
			Mail:     "satoshi.nakamoto@wierbicki.org",
			Password: string(genesisPass),
			Admin:    true,
		}); err != nil {
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
		Admin:    false,
	})
	if err != nil {
		return nil, err
	}
	return &entity.User{
		Id:       strconv.FormatInt(row.ID, 10),
		Username: row.Name,
		Email:    row.Mail,
		Password: []byte(row.Password),
		Admin:    row.Admin,
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
		Admin:    row.Admin,
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
		Admin:    row.Admin,
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
