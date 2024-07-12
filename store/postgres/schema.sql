CREATE SCHEMA IF NOT EXISTS vote_decrypt;

CREATE TABLE IF NOT EXISTS vote_decrypt.poll(
    -- The poll id, is a string like 'mydomain.com/42
    id  TEXT PRIMARY KEY,

    -- Key data
    key BYTEA NOT NULL,

    -- Hash of the signed poll data
    hash BYTEA Null
);

