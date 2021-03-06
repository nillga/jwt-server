// Code generated by sqlc. DO NOT EDIT.
// source: query.sql

package postgresql

import (
	"context"
)

const createUser = `-- name: CreateUser :one
INSERT INTO public.users (
    name, email, password, admin
) VALUES (
          $1, $2, $3, $4
          )
ON CONFLICT (name) DO NOTHING
RETURNING id, name, email, password, admin
`

type CreateUserParams struct {
	Name     string
	Mail     string
	Password string
	Admin    bool
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser,
		arg.Name,
		arg.Mail,
		arg.Password,
		arg.Admin,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Mail,
		&i.Password,
		&i.Admin,
	)
	return i, err
}

const deleteUser = `-- name: DeleteUser :exec
DELETE FROM public.users
WHERE id = $1
`

func (q *Queries) DeleteUser(ctx context.Context, id int64) error {
	_, err := q.db.ExecContext(ctx, deleteUser, id)
	return err
}

const findUser = `-- name: FindUser :one
SELECT id, name, email, password, admin FROM public.users
WHERE name = $1 OR email = $2 LIMIT 1
`

type FindUserParams struct {
	Name string
	Mail string
}

func (q *Queries) FindUser(ctx context.Context, arg FindUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, findUser, arg.Name, arg.Mail)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Mail,
		&i.Password,
		&i.Admin,
	)
	return i, err
}

const findUserById = `-- name: FindUserById :one
SELECT id, name, email, password, admin FROM public.users
WHERE id = $1 LIMIT 1
`

func (q *Queries) FindUserById(ctx context.Context, id int64) (User, error) {
	row := q.db.QueryRowContext(ctx, findUserById, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Mail,
		&i.Password,
		&i.Admin,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :exec
UPDATE public.users
SET password = $2 WHERE id = $1
`

type UpdateUserParams struct {
	ID       int64
	Password string
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) error {
	_, err := q.db.ExecContext(ctx, updateUser, arg.ID, arg.Password)
	return err
}

const elevateUser = `-- name: ElevateUser :exec
UPDATE public.users 
SET admin = NOT admin WHERE id = $1
`


func (q *Queries) ElevateUser(ctx context.Context, id int64) error {
	_, err := q.db.ExecContext(ctx, elevateUser, id)
	return err
}

const getAllUsers = `-- name: AllUsers :many
SELECT id, name, admin FROM public.users
`

func (q *Queries) AllUsers(ctx context.Context) ([]User, error) {
	rows, err := q.db.QueryContext(ctx, getAllUsers)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var items []User
    for rows.Next() {
        var i User
        if err := rows.Scan(&i.ID, &i.Name, &i.Admin); err != nil {
            return nil, err
        }
        items = append(items, i)
    }
    if err := rows.Close(); err != nil {
        return nil, err
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return items, nil
}