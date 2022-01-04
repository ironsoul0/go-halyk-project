package main

import (
	"banking-service/util"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
)

type Server struct {
	repo *Repo

	redisConn     *redis.Client
	accessSecret  string
	refreshSecret string
	accessTtl     time.Duration
	refreshTtl    time.Duration
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	queryId := vars["id"]

	id, err := strconv.ParseInt(queryId, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user, err := s.repo.getUser(id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	buf, err := json.MarshalIndent(user, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, string(buf))
}

func (s *Server) authorizatonCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractToken(r)
		if err != nil {
			log.Printf("Extract access token error: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		tokenPayload, err := s.parseToken(token, true)
		if err != nil {
			log.Printf("Parse access token error: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), "id", tokenPayload.ID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func main() {
	config, err := util.LoadConfig(".")
	if err != nil {
		log.Fatalf("Loading config error: %v", err)
	}

	repo, err := NewRepo(config.DBSource)
	if err != nil {
		log.Fatalf("Postgres error: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddress,
		Password: "",
		DB:       0,
	})

	_, err = client.Ping().Result()
	if err != nil {
		log.Fatalf("Ping redis error: %v", err)
	}

	server := &Server{
		repo:          repo,
		accessSecret:  config.AccessSecret,
		refreshSecret: config.RefreshSecret,
		redisConn:     client,
		accessTtl:     24 * time.Hour,
		refreshTtl:    24 * time.Hour,
	}

	r := mux.NewRouter()

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/login", server.login).Methods("POST")
	authRouter.HandleFunc("/update", server.update).Methods("POST")
	authRouter.HandleFunc("/register", server.register).Methods("POST")

	appRouter := r.PathPrefix("/app").Subrouter()
	appRouter.Use(server.authorizatonCheckMiddleware)

	appRouter.HandleFunc("/user/{id:[0-9]+}", server.getUser).Methods("GET")

	http.ListenAndServe(fmt.Sprintf(":%s", config.Port), r)
}
