package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func (s *Server) insertToken(id int64, token string) error {
	key := fmt.Sprintf("user:%d", id)

	return s.redisConn.Set(key, token, s.refreshTtl).Err()
}

func (s *Server) generateAndSendTokens(user *User, w http.ResponseWriter) {
	accessTokenExp := time.Now().Add(s.accessTtl).Unix()

	payload := &TokenPayload{
		ID:       user.ID,
		IIN:      user.IIN,
		Username: user.Username,
		Role:     user.Role,
	}
	buf, _ := json.Marshal(payload)

	accessTokenClaims := jwt.MapClaims{}
	accessTokenClaims["payload"] = string(buf)
	accessTokenClaims["iat"] = time.Now().Unix()
	accessTokenClaims["exp"] = accessTokenExp
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	accessSignedToken, err := accessToken.SignedString([]byte(s.accessSecret))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Coundn't create token. Error: %v", err)
		return
	}

	refreshTokenExp := time.Now().Add(s.refreshTtl).Unix()
	refreshTokenClaims := jwt.MapClaims{}
	refreshTokenClaims["payload"] = string(buf)
	refreshTokenClaims["iat"] = time.Now().Unix()
	refreshTokenClaims["exp"] = refreshTokenExp
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)

	refreshSignedToken, err := refreshToken.SignedString([]byte(s.refreshSecret))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Coundn't create token. Error: %v", err)
		return
	}

	if err := s.insertToken(user.ID, refreshSignedToken); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Coundn't insert token in redis. Error: %v", err)
		return
	}

	response := struct {
		AccessToken  string `json:"access"`
		RefreshToken string `json:"refresh"`
	}{
		AccessToken:  accessSignedToken,
		RefreshToken: refreshSignedToken,
	}

	buf, err = json.MarshalIndent(&response, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, string(buf))
}

func (s *Server) findToken(id int64, token string) bool {
	key := fmt.Sprintf("user:%d", id)

	value, err := s.redisConn.Get(key).Result()
	if err != nil {
		return false
	}

	return token == value
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	id, _ := s.repo.loginUser(username, password)
	user, err := s.repo.getUser(id)

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Invalid auth")
		return
	}

	s.generateAndSendTokens(user, w)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	IIN := r.FormValue("IIN")

	if username == "" || password == "" || IIN == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Got empty input"))
		return
	}

	id, err := s.repo.createUser(username, password, IIN)
	if errors.Is(err, usernameOrIINTaken) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Username or IIN was already taken")
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User %d was created", id)
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh")

	//checking update token
	tokenPayload, err := s.parseToken(refreshToken, false)
	if err != nil {
		log.Printf("Parse refresh token error: %v", err)
		w.WriteHeader(http.StatusMovedPermanently)
		w.Header().Add("Location", "/login")
		return
	}

	// find token in Redis
	ok := s.findToken(tokenPayload.ID, refreshToken)
	if !ok {
		log.Printf("Getting refresh token failed")
		w.WriteHeader(http.StatusMovedPermanently)
		w.Header().Add("Location", "/login")
		return
	}

	user, err := s.repo.getUser(tokenPayload.ID)
	if err != nil {
		log.Printf("Getting user failed")
		w.WriteHeader(http.StatusMovedPermanently)
		w.Header().Add("Location", "/login")
		return
	}

	s.generateAndSendTokens(user, w)
}
