-- name: FindUserById :one
SELECT * FROM users
WHERE id = $1 LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (
    name, mail, password
) VALUES (
          $1, $2, $3
          )
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;

-- name: FindUser :one
SELECT * FROM users
WHERE name = $1 OR mail = $2 LIMIT 1;

-- name: UpdateUser :exec
UPDATE users
SET password = $2 WHERE id = $1;