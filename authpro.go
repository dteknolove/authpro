package authpro

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/o1egl/paseto"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

type auth struct {
	DB *pgxpool.Pool
	W  http.ResponseWriter
	R  *http.Request
}

type Auth interface {
	TokenJWT(claimName string, userId uuid.UUID) (string, string, error)
	ParseJWT(claimName string, tokenString string) (string, float64, error)
	ExtractJWT() (string, error)
	MiddlewarePerm(claimName string) bool
	HashPassword(password string) ([]byte, error)
	ComparePassword(userPassword []byte, dtoPassword string) error
	RandomPassword(length int) (string, error)
	UUID(param string) (uuid.UUID, error)
	MiddlewareApiKey(apiKeyName, apiValueName string, r *http.Request) (bool, string)
}

func NewAuth(w http.ResponseWriter, r *http.Request) Auth {
	return &auth{
		W: w,
		R: r,
	}
}

const (
	Content  = "Content-Type"
	AppJson  = "application/json"
	RandChar = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func (a *auth) TokenJWT(claimName string, userId uuid.UUID) (string, string, error) {
	DotENV()
	var err error
	privateKey := []byte(os.Getenv("JWT_KEY_SECRET"))
	privateRefreshKey := []byte(os.Getenv("JWT_REFRESH_KEY_SECRET"))

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims[claimName] = userId
	claims["exp"] = time.Now().Add(time.Hour * 2).Unix()
	accessTokenString, errAuthToken := token.SignedString(privateKey)
	if errAuthToken != nil {
		err = errAuthToken
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	refreshClaims["ref_"+claimName] = userId
	refreshClaims["ref_exp"] = time.Now().Add(time.Hour * 2).Unix()
	refreshTokenString, errRefreshToken := refreshToken.SignedString(privateRefreshKey)
	if errRefreshToken != nil {
		err = errRefreshToken
	}

	return accessTokenString, refreshTokenString, err
}

func (a *auth) ParseJWT(paramId string, tokenString string) (string, float64, error) {
	DotENV()
	var err error
	jwtKey := os.Getenv("JWT_KEY_SECRET")
	token, errParse := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err = errors.New(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
			slog.Error(err.Error(), "error parse token")
		}
		secretKey := []byte(jwtKey)
		return secretKey, nil
	})
	if errParse != nil {
		err = errParse
		slog.Error(errParse.Error(), "error parse token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		err = errors.New(strings.ToLower("error claim token"))
		slog.Error(err.Error(), "error claim token")
	}
	jwtUserId := claims[paramId].(string)
	jwtExp := claims["exp"].(float64)

	return jwtUserId, jwtExp, err
}

func (a *auth) ExtractJWT() (string, error) {
	authHeader := a.R.Header.Get("Authorization")
	var err error
	errHeader := checkAuthHeader(authHeader)
	authHeaderParts := strings.Split(authHeader, " ")
	errBearer := checkBearer(authHeaderParts)
	if len(authHeaderParts) < 2 {
		err = errors.New(fmt.Sprintf("%s: %s", "error token not found", errHeader))
		slog.Error(err.Error(), "error token not found")
	}
	if errBearer != nil {
		err = errBearer
		slog.Error(errBearer.Error(), "error bearer token")
	}
	tokenString := authHeaderParts[1]
	return tokenString, err
}
func checkAuthHeader(authHeader string) error {
	if len(authHeader) <= 5 {
		return errors.New("length of authHeader exceeds 5 characters token is not valid")
	}
	return nil
}
func checkBearer(str []string) error {
	if len(str) != 2 || str[0] != "Bearer" {
		return errors.New("invalid bearer token")
	}
	return nil
}

func (a *auth) MiddlewarePerm(paramId string) bool {
	userId := chi.URLParam(a.R, paramId)
	jwtUserId := a.R.Context().Value("jwt_" + paramId).(string)
	if userId != jwtUserId {
		response := map[string]interface{}{
			"data":       "ERROR PERMISSION",
			"message":    "You are not authorize",
			"statusCode": http.StatusUnauthorized,
			"success":    false,
		}
		a.W.Header().Set(Content, AppJson)
		a.W.WriteHeader(http.StatusUnauthorized)
		err := json.NewEncoder(a.W).Encode(response)
		if err != nil {
			slog.Error(err.Error())
			http.Error(a.W, err.Error(), http.StatusInternalServerError)
		}
		return false
	}
	return true
}

func (a *auth) MiddlewareApiKey(apiKeyName, apiValueName string, r *http.Request) (bool, string) {
	b := true
	var message string
	getApiHeader := r.Header.Get(apiKeyName)
	if getApiHeader == "" {
		b = false
		message = "error header is empty"
	}
	apiKeyHeader := strings.Split(getApiHeader, " ")
	apiHeaderValue := apiKeyHeader[0]
	if len(apiHeaderValue) <= 0 {
		b = false
		message = "error header has no length"
	}
	if apiValueName != apiHeaderValue {
		b = false
		message = "invalid api key"
	}
	return b, message
}

func (a *auth) UUID(param string) (uuid.UUID, error) {
	var err error
	id := chi.URLParam(a.R, param)

	UUID, errParseUUID := uuid.FromString(id)
	if errParseUUID != nil {
		err = errors.New("error parse uuid")
		return uuid.Nil, err
	}
	return UUID, err
}

func (a *auth) HashPassword(password string) ([]byte, error) {
	var errHash error
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		errHash = err
		slog.Error(err.Error(), "error hash password")
	}
	return hashedPassword, errHash
}

func (a *auth) ComparePassword(userPassword []byte, dtoPassword string) error {
	err := bcrypt.CompareHashAndPassword(userPassword, []byte(dtoPassword))
	return err
}

func (a *auth) RandomPassword(length int) (string, error) {
	var errRand error
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)
	if err != nil {
		errRand = err
		slog.Error(err.Error(), fmt.Sprintf("error random crypto: %s", err.Error()))
	}

	charsetLength := len(RandChar)
	for i := 0; i < length; i++ {
		buffer[i] = RandChar[int(buffer[i])%charsetLength]
	}
	return string(buffer), errRand
}

//Paseto

type PasetoMaker struct {
	paseto       *paseto.V2
	symmetricKey []byte
}

type Payload struct {
	ID        uuid.UUID `json:"ID"`
	UserID    uuid.UUID `json:"userID"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

func NewPasetoMaker(symmetricKey string) (*PasetoMaker, error) {
	if len(symmetricKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: must be exactly %d characters", chacha20poly1305.KeySize)
	}

	maker := &PasetoMaker{
		paseto:       paseto.NewV2(),
		symmetricKey: []byte(symmetricKey),
	}

	return maker, nil
}

func NewPasetoPayload(userID uuid.UUID, duration time.Duration) (*Payload, error) {
	tokenID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenID,
		UserID:    userID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}
	return payload, nil
}
func (maker *PasetoMaker) CreatePasetoToken(userID uuid.UUID, duration time.Duration) (string, error) {
	payload, err := NewPasetoPayload(userID, duration)
	if err != nil {
		return "", err
	}

	return maker.paseto.Encrypt(maker.symmetricKey, payload, nil)
}
func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return errors.New("expired")
	}
	return nil
}

func (maker *PasetoMaker) VerifyPasetoToken(token string) (*Payload, error) {
	payload := &Payload{}

	err := maker.paseto.Decrypt(token, maker.symmetricKey, payload, nil)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func DotENV() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err, "error load .env")
	}
}
