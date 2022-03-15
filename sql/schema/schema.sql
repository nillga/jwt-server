-- +migrate Up
CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    name        text      NOT NULL,
    mail        text      NOT NULL,
    password    text      NOT NULL,
    admin       boolean   NOT NULL
);

INSERT INTO users (
    name="genesisAdmin", mail="satoshi.nakamoto@wierbicki.org", password="", admin=true
)