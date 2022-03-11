package repository

import "github.com/nillga/jwt-server/entity"

type postgresRepo struct{
	postgresUri string
}

// TODO: implement

func NewPostgresRepo(postgresUri string) JwtRepository {
	return &postgresRepo{
		postgresUri: postgresUri,
	}
}

func (p *postgresRepo) Store(user *entity.User) (*entity.User, error) {
	return nil, nil
}

func (p *postgresRepo) Find(user *entity.User) (*entity.User, error) {
	return nil, nil
}

func (p *postgresRepo) FindById(id string) (*entity.User, error) {
	return nil, nil
}

func (p *postgresRepo) Delete(id string) error {
	return nil
}

func (m *postgresRepo) UpdateUser(id string, user *entity.User) error {
	return nil
}