package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func (s *Server) insertToken(id int64, token string) error {
	key := fmt.Sprintf("user:%d", id)

	return s.redisConn.Set(key, token, s.refreshTtl).Err()
}

func (s *Server) generateAndSendTokens(id int64, w http.ResponseWriter) {
	accessTokenExp := time.Now().Add(s.accessTtl).Unix()

	accessTokenClaims := jwt.MapClaims{}
	accessTokenClaims["id"] = id
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
	refreshTokenClaims["id"] = id
	refreshTokenClaims["iat"] = time.Now().Unix()
	refreshTokenClaims["exp"] = refreshTokenExp
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)

	refreshSignedToken, err := refreshToken.SignedString([]byte(s.refreshSecret))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Coundn't create token. Error: %v", err)
		return
	}

	if err := s.insertToken(id, refreshSignedToken); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Coundn't insert token in redis. Error: %v", err)
		return
	}

	fmt.Fprintf(w, "Access token: %s\nRefresh token: %s", accessSignedToken, refreshSignedToken)
}

func (s *Server) findToken(id int64, token string) bool {
	key := fmt.Sprintf("user:%d", id)

	value, err := s.redisConn.Get(key).Result()
	if err != nil {
		return false
	}

	return token == value
}

func extractToken(r *http.Request) (token string, err error) {
	header := string(r.Header.Get("Authorization"))
	if header == "" {
		err = fmt.Errorf("Authorization header not found")
		return
	}
	parsedHeader := strings.Split(header, " ")
	if len(parsedHeader) != 2 || parsedHeader[0] != "Bearer" {
		err = fmt.Errorf("Invalid authorization header")
		return
	}

	token = parsedHeader[1]
	return
}

func (s *Server) parseToken(token string, isAccess bool) (int64, error) {
	JWTToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Failed to extract token metadata, unexpected signing method: %v", token.Header["alg"])
		}
		if isAccess {
			return []byte(s.accessSecret), nil
		}
		return []byte(s.refreshSecret), nil
	})

	if err != nil {
		return 0, err
	}

	claims, ok := JWTToken.Claims.(jwt.MapClaims)

	var userId float64

	if ok && JWTToken.Valid {
		userId, ok = claims["id"].(float64)
		if !ok {
			return 0, fmt.Errorf("Field id not found")
		}

		exp, ok := claims["exp"].(float64)
		if !ok {
			return 0, fmt.Errorf("Field exp not found")
		}

		expiredTime := time.Unix(int64(exp), 0)
		log.Printf("Expired: %v", expiredTime)
		if time.Now().After(expiredTime) {
			return 0, fmt.Errorf("Token expired")
		}
		return int64(userId), nil
	}

	return 0, fmt.Errorf("Invalid token")
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	id, err := s.repo.loginUser(username, password)

	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Invalid auth")
		return
	}

	s.generateAndSendTokens(id, w)
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
	id, err := s.parseToken(refreshToken, false)
	if err != nil {
		log.Printf("Parse refresh token error: %v", err)
		w.WriteHeader(http.StatusMovedPermanently)
		w.Header().Add("Location", "/login")
		return
	}

	// find token in Redis
	ok := s.findToken(id, refreshToken)
	if !ok {
		log.Printf("Getting refresh token failed")
		w.WriteHeader(http.StatusMovedPermanently)
		w.Header().Add("Location", "/login")
		return
	}

	s.generateAndSendTokens(id, w)
}
