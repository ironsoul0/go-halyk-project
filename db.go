package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx"
	"github.com/jackc/pgx/v4/pgxpool"
)

var usernameOrIINTaken error = errors.New("username taken")
var walletTaken error = errors.New("wallet taken")
var invalidCreds error = errors.New("invalid creds")

type Repo struct {
	db *pgxpool.Pool
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	IIN      string `json:"IIN"`
	Role     string `json:"role"`
	Password string `json:"-"`
}

func NewRepo(DSN string) (*Repo, error) {
	config, err := pgxpool.ParseConfig(DSN)
	if err != nil {
		return nil, err
	}

	config.MaxConns = 25
	config.MaxConnLifetime = 5 * time.Minute

	db, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(context.Background()); err != nil {
		return nil, err
	}

	return &Repo{
		db: db,
	}, nil
}

func (r *Repo) getUser(id int64) (*User, error) {
	var query string
	query = "SELECT id, username, password, iin, role FROM users WHERE id = $1"
	user := &User{}

	err := r.db.QueryRow(context.Background(), query, id).Scan(&user.ID, &user.Username, &user.Password, &user.IIN, &user.Role)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("getUser: %w", err)
	}

	return user, nil
}

func (r *Repo) loginUser(username string, password string) (int64, error) {
	query := "SELECT id from users WHERE username = $1 AND password = $2"
	var id int64
	err := r.db.QueryRow(context.Background(), query, username, password).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("loginUser: %w", invalidCreds)
		}
		return 0, fmt.Errorf("loginUser: %w", err)
	}
	return id, nil
}

func (r *Repo) createUser(username string, password string, IIN string) (int64, error) {
	var query string
	var err error

	query = "SELECT COUNT(*) FROM users WHERE username = $1 OR iin = $2"
	var total int
	err = r.db.QueryRow(context.Background(), query, username, IIN).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("createUser: %w", err)
	}
	if total != 0 {
		return 0, fmt.Errorf("createUser: %w", usernameOrIINTaken)
	}

	query = "INSERT INTO users (username, password, iin) VALUES ($1, $2, $3) RETURNING id"
	var id int64
	err = r.db.QueryRow(context.Background(), query, username, password, IIN).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("createUser: %w", err)
	}

	return id, nil
}
