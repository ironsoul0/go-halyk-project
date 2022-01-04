package main

import (
	"banking-service/util"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/mux"
)

type Server struct {
	repo *Repo

	redisConn           *redis.Client
	accessSecret        string
	refreshSecret       string
	accessTtl           time.Duration
	refreshTtl          time.Duration
	transactionsService string
}

func (s *Server) fetchWallets(authHeader string) ([]*Wallet, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/wallets", s.transactionsService), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", authHeader)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	wallets := make([]*Wallet, 0)
	json.Unmarshal(body, &wallets)

	return wallets, nil
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Auth header", r.Header.Get("Authorization"))
	wallets, err := s.fetchWallets(r.Header.Get("Authorization"))

	fmt.Println("wallets", wallets)
	fmt.Println("err", err)

	payload, err := getPayload(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	user, err := s.repo.getUser(payload.ID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
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

func (s *Server) authorizationCheckMiddleware(next http.Handler) http.Handler {
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

		ctx := context.WithValue(r.Context(), "payload", tokenPayload)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) adminCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.Context().Value("payload").(*TokenPayload)

		if payload == nil || payload.Role != ADMIN_ROLE {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Admin access required")
			return
		}

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
		repo:                repo,
		accessSecret:        config.AccessSecret,
		refreshSecret:       config.RefreshSecret,
		redisConn:           client,
		accessTtl:           24 * time.Hour,
		refreshTtl:          24 * time.Hour,
		transactionsService: config.TransactionsService,
	}

	r := mux.NewRouter()

	authRouter := r.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/login", server.login).Methods("POST")
	authRouter.HandleFunc("/update", server.update).Methods("POST")
	authRouter.HandleFunc("/register", server.register).Methods("POST")

	appRouter := r.PathPrefix("/").Subrouter()
	appRouter.Use(server.authorizationCheckMiddleware)
	appRouter.HandleFunc("/profile", server.profile).Methods("GET")

	adminRouter := r.PathPrefix("/").Subrouter()
	adminRouter.Use(server.authorizationCheckMiddleware, server.adminCheckMiddleware)
	adminRouter.HandleFunc("/user/{id:[0-9]+}", server.getUser).Methods("GET")

	http.ListenAndServe(fmt.Sprintf(":%s", config.Port), r)
}
