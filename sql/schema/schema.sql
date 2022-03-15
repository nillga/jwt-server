-- +migrate Up
CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    name        text      NOT NULL,
    mail        text      NOT NULL,
    password    text      NOT NULL,
    admin       boolean   NOT NULL
);