-- name: FindUserById :one
SELECT * FROM users
WHERE id = $1 LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (
    name, email, password, isAdmin
) VALUES (
          $1, $2, $3, $4
          )
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: FindUser :one
SELECT * FROM users
WHERE name = $1 OR email = $2 LIMIT 1;

-- name: UpdateUser :exec
UPDATE users
SET password = $2 WHERE id = $1;