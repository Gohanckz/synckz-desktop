package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// UserType define los tipos de usuario del sistema
type UserType string

const (
	UserTypeFree       UserType = "free"
	UserTypePro        UserType = "pro"
	UserTypeEnterprise UserType = "enterprise"
	UserTypeAdmin      UserType = "admin"
)

// User estructura básica para usuarios
type User struct {
	ID       uint     `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Level    int      `json:"level"`
	Credits  int      `json:"credits"`
	UserType UserType `json:"user_type"`
}

// LoginRequest estructura para peticiones de login
type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest estructura para peticiones de refresh token
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LoginResponse estructura para respuestas de login
type LoginResponse struct {
	Success      bool   `json:"success"`
	User         *User  `json:"user,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"` // segundos hasta expiración
	Error        string `json:"error,omitempty"`
}

// RegisterRequest estructura para peticiones de registro
type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// hashPassword crea un hash seguro de la contraseña usando bcrypt
func hashPassword(password string) (string, error) {
	// Usamos un cost de 12 para equilibrar seguridad y rendimiento
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// verifyPassword verifica si una contraseña coincide con su hash
func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// JWTClaims estructura para los claims del JWT
type JWTClaims struct {
	UserID   uint     `json:"user_id"`
	Email    string   `json:"email"`
	Username string   `json:"username"`
	UserType UserType `json:"user_type"`
	Level    int      `json:"level"`
	jwt.RegisteredClaims
}

// TokenConfig configuración de duración de tokens por tipo de usuario
var TokenConfig = map[UserType]struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}{
	UserTypeFree:       {AccessTokenDuration: 15 * time.Minute, RefreshTokenDuration: 7 * 24 * time.Hour},   // 15min / 7 días
	UserTypePro:        {AccessTokenDuration: 1 * time.Hour, RefreshTokenDuration: 30 * 24 * time.Hour},      // 1h / 30 días
	UserTypeEnterprise: {AccessTokenDuration: 2 * time.Hour, RefreshTokenDuration: 90 * 24 * time.Hour},      // 2h / 90 días
	UserTypeAdmin:      {AccessTokenDuration: 30 * time.Minute, RefreshTokenDuration: 1 * 24 * time.Hour},    // 30min / 1 día (más seguro)
}

// JWT secret key - en producción debería venir de variables de entorno
var jwtSecret []byte

// Django integration variables
var (
	djangoAPIURL     string
	djangoEnabled    bool
	djangoClient     *DjangoClient
)

// initJWTSecret inicializa la clave secreta para JWT
func initJWTSecret() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Generar una clave temporal para desarrollo
		tempSecret := make([]byte, 32)
		rand.Read(tempSecret)
		jwtSecret = tempSecret
		log.Println("⚠️  Using temporary JWT secret - set JWT_SECRET env var for production")
	} else {
		jwtSecret = []byte(secret)
		log.Println("🔑 JWT secret loaded from environment")
	}
}

// initDjangoClient inicializa el cliente para Django API
func initDjangoClient() {
	djangoAPIURL = os.Getenv("DJANGO_API_URL")
	djangoEnabledStr := os.Getenv("DJANGO_AUTH_ENABLED")

	djangoEnabled = djangoEnabledStr == "true"

	if djangoEnabled && djangoAPIURL != "" {
		djangoClient = NewDjangoClient(djangoAPIURL)
		log.Printf("🌐 Django authentication enabled - API: %s", djangoAPIURL)
	} else {
		log.Println("🔒 Local-only authentication mode (Django integration disabled)")
	}
}

// generateAccessToken genera un JWT access token
func generateAccessToken(user *User) (string, error) {
	config := TokenConfig[user.UserType]
	expirationTime := time.Now().Add(config.AccessTokenDuration)

	claims := &JWTClaims{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		UserType: user.UserType,
		Level:    user.Level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "synckz-auth-service",
			Subject:   fmt.Sprintf("user:%d", user.ID),
			ID:        generateTokenID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// generateRefreshToken genera un JWT refresh token y lo almacena
func generateRefreshToken(user *User) (string, error) {
	config := TokenConfig[user.UserType]
	expirationTime := time.Now().Add(config.RefreshTokenDuration)
	tokenID := generateTokenID()

	claims := &JWTClaims{
		UserID:   user.ID,
		Email:    user.Email,
		Username: user.Username,
		UserType: user.UserType,
		Level:    user.Level,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "synckz-auth-service",
			Subject:   fmt.Sprintf("refresh:%d", user.ID),
			ID:        tokenID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	// Almacenar el refresh token para control de rotación
	refreshTokenStore.storeRefreshToken(tokenID, user.ID, user.UserType, expirationTime)

	return tokenString, nil
}

// generateTokenID genera un ID único para el token
func generateTokenID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// getUserType determina el tipo de usuario basado en email y level
func getUserType(user *StoredUser) UserType {
	// Admin users
	if user.Email == "admin@synckz.com" || user.Level >= 10 {
		return UserTypeAdmin
	}

	// Demo user (treat as pro for now)
	if user.Email == "demo@synckz.com" {
		return UserTypePro
	}

	// Based on level for other users
	if user.Level >= 8 {
		return UserTypeEnterprise
	} else if user.Level >= 5 {
		return UserTypePro
	}

	return UserTypeFree
}

// getUserTypeFromStored helper function to determine user type from StoredUser
func getUserTypeFromStored(user *StoredUser) UserType {
	// Admin users
	if user.Email == "admin@synckz.com" || user.Level >= 10 {
		return UserTypeAdmin
	}

	// Demo user (treat as pro for now)
	if user.Email == "demo@synckz.com" {
		return UserTypePro
	}

	// Based on level for other users
	if user.Level >= 8 {
		return UserTypeEnterprise
	} else if user.Level >= 5 {
		return UserTypePro
	}

	return UserTypeFree
}

// validateJWT valida y parsea un JWT token
func validateJWT(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// UserStore estructura para almacenar usuarios de forma segura
type UserStore struct {
	users map[string]*StoredUser
	mutex sync.RWMutex
}

// StoredUser representa un usuario almacenado con contraseña hasheada
type StoredUser struct {
	ID             uint   `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	HashedPassword string `json:"-"` // No se serializa en JSON por seguridad
	Level          int    `json:"level"`
	Credits        int    `json:"credits"`
}

// RefreshTokenEntry almacena un refresh token activo
type RefreshTokenEntry struct {
	TokenID   string    `json:"token_id"`
	UserID    uint      `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	UserType  UserType  `json:"user_type"`
}

// RefreshTokenStore almacena refresh tokens activos de forma segura
type RefreshTokenStore struct {
	tokens map[string]*RefreshTokenEntry
	mutex  sync.RWMutex
}

// BlacklistedTokenEntry almacena un token JWT en blacklist
type BlacklistedTokenEntry struct {
	TokenID   string    `json:"token_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

// TokenBlacklist almacena tokens JWT invalidados antes de su expiración
type TokenBlacklist struct {
	tokens map[string]*BlacklistedTokenEntry
	mutex  sync.RWMutex
}

// Base de datos en memoria para usuarios (en producción usaríamos una BD real)
var userStore = &UserStore{
	users: make(map[string]*StoredUser),
}

// Store seguro para refresh tokens activos
var refreshTokenStore = &RefreshTokenStore{
	tokens: make(map[string]*RefreshTokenEntry),
}

// Blacklist para tokens JWT invalidados antes de expiración
var tokenBlacklist = &TokenBlacklist{
	tokens: make(map[string]*BlacklistedTokenEntry),
}

// initializeUsers inicializa los usuarios de demo con contraseñas hasheadas
func initializeUsers() {
	userStore.mutex.Lock()
	defer userStore.mutex.Unlock()

	// Hash de las contraseñas de demo
	adminHash, _ := hashPassword("admin123")
	demoHash, _ := hashPassword("demo123")

	// Crear usuarios de demo
	userStore.users["admin@synckz.com"] = &StoredUser{
		ID:             1,
		Username:       "admin",
		Email:          "admin@synckz.com",
		HashedPassword: adminHash,
		Level:          10,
		Credits:        999999,
	}

	userStore.users["demo@synckz.com"] = &StoredUser{
		ID:             2,
		Username:       "demo",
		Email:          "demo@synckz.com",
		HashedPassword: demoHash,
		Level:          5,
		Credits:        1000,
	}

	log.Println("🔐 Demo users initialized with hashed passwords")
}

// getUser obtiene un usuario por email de forma segura
func (us *UserStore) getUser(email string) (*StoredUser, bool) {
	us.mutex.RLock()
	defer us.mutex.RUnlock()
	user, exists := us.users[email]
	return user, exists
}

// addUser agrega un nuevo usuario de forma segura
func (us *UserStore) addUser(user *StoredUser) {
	us.mutex.Lock()
	defer us.mutex.Unlock()
	us.users[user.Email] = user
}

// Métodos del RefreshTokenStore

// storeRefreshToken almacena un refresh token activo
func (rts *RefreshTokenStore) storeRefreshToken(tokenID string, userID uint, userType UserType, expiresAt time.Time) {
	rts.mutex.Lock()
	defer rts.mutex.Unlock()

	rts.tokens[tokenID] = &RefreshTokenEntry{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		IssuedAt:  time.Now(),
		UserType:  userType,
	}
}

// validateRefreshToken valida y consume un refresh token (token rotation)
func (rts *RefreshTokenStore) validateRefreshToken(tokenID string) (*RefreshTokenEntry, bool) {
	rts.mutex.Lock()
	defer rts.mutex.Unlock()

	entry, exists := rts.tokens[tokenID]
	if !exists {
		return nil, false
	}

	// Verificar expiración
	if time.Now().After(entry.ExpiresAt) {
		delete(rts.tokens, tokenID) // Limpiar token expirado
		return nil, false
	}

	// Token rotation: remover el token usado (solo se puede usar una vez)
	delete(rts.tokens, tokenID)

	return entry, true
}

// revokeUserTokens revoca todos los refresh tokens de un usuario (para logout)
func (rts *RefreshTokenStore) revokeUserTokens(userID uint) {
	rts.mutex.Lock()
	defer rts.mutex.Unlock()

	for tokenID, entry := range rts.tokens {
		if entry.UserID == userID {
			delete(rts.tokens, tokenID)
		}
	}
}

// cleanExpiredTokens limpia tokens expirados (debe llamarse periódicamente)
func (rts *RefreshTokenStore) cleanExpiredTokens() {
	rts.mutex.Lock()
	defer rts.mutex.Unlock()

	now := time.Now()
	for tokenID, entry := range rts.tokens {
		if now.After(entry.ExpiresAt) {
			delete(rts.tokens, tokenID)
		}
	}
}

// Métodos del TokenBlacklist

// blacklistToken agrega un token a la blacklist
func (tb *TokenBlacklist) blacklistToken(tokenID string, expiresAt time.Time, reason string) {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	tb.tokens[tokenID] = &BlacklistedTokenEntry{
		TokenID:   tokenID,
		ExpiresAt: expiresAt,
		Reason:    reason,
	}
}

// isTokenBlacklisted verifica si un token está en la blacklist
func (tb *TokenBlacklist) isTokenBlacklisted(tokenID string) bool {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()

	entry, exists := tb.tokens[tokenID]
	if !exists {
		return false
	}

	// Si el token expiró naturalmente, ya no es necesario mantenerlo en blacklist
	if time.Now().After(entry.ExpiresAt) {
		delete(tb.tokens, tokenID)
		return false
	}

	return true
}

// cleanExpiredBlacklistedTokens limpia tokens blacklisted que ya expiraron naturalmente
func (tb *TokenBlacklist) cleanExpiredBlacklistedTokens() {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	for tokenID, entry := range tb.tokens {
		if now.After(entry.ExpiresAt) {
			delete(tb.tokens, tokenID)
		}
	}
}

// Rate limiting structures
type RateLimiter struct {
	visitors map[string]*Visitor
	mutex    sync.RWMutex
}

type Visitor struct {
	lastSeen time.Time
	attempts int
	blocked  bool
}

var rateLimiter = &RateLimiter{
	visitors: make(map[string]*Visitor),
}

// Rate limiting configuration
const (
	maxAttempts     = 5               // Maximum login attempts
	blockDuration   = 15 * time.Minute // Block duration for failed attempts
	cleanupInterval = 30 * time.Minute // Cleanup old entries
)

// cleanupVisitors removes old visitor entries
func (rl *RateLimiter) cleanupVisitors() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	cutoff := time.Now().Add(-cleanupInterval)
	for ip, visitor := range rl.visitors {
		if visitor.lastSeen.Before(cutoff) && !visitor.blocked {
			delete(rl.visitors, ip)
		}
	}
}

// isBlocked checks if an IP is currently blocked
func (rl *RateLimiter) isBlocked(ip string) bool {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	visitor, exists := rl.visitors[ip]
	if !exists {
		return false
	}

	// Check if block period has expired
	if visitor.blocked && time.Since(visitor.lastSeen) > blockDuration {
		// Reset visitor
		visitor.blocked = false
		visitor.attempts = 0
		return false
	}

	return visitor.blocked
}

// recordAttempt records a login attempt
func (rl *RateLimiter) recordAttempt(ip string, successful bool) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	visitor, exists := rl.visitors[ip]
	if !exists {
		visitor = &Visitor{}
		rl.visitors[ip] = visitor
	}

	visitor.lastSeen = time.Now()

	if successful {
		// Reset on successful login
		visitor.attempts = 0
		visitor.blocked = false
	} else {
		visitor.attempts++
		if visitor.attempts >= maxAttempts {
			visitor.blocked = true
			log.Printf("🚫 IP %s blocked after %d failed attempts", ip, visitor.attempts)
		}
	}
}

// rateLimitMiddleware implements rate limiting for sensitive endpoints
func rateLimitMiddleware() gin.HandlerFunc {
	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		for {
			<-ticker.C
			rateLimiter.cleanupVisitors()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if rateLimiter.isBlocked(ip) {
			c.JSON(429, LoginResponse{
				Success: false,
				Error:   "Too many failed attempts. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Validation functions
func isValidEmail(email string) bool {
	// Basic email validation with regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return false
	}

	// Additional checks
	if len(email) > 254 { // RFC 5321 limit
		return false
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	local := parts[0]
	domain := parts[1]

	// Local part validations
	if len(local) > 64 || len(local) == 0 {
		return false
	}

	// Domain part validations
	if len(domain) > 253 || len(domain) == 0 {
		return false
	}

	return true
}

func isValidPassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long"
	}

	if len(password) > 128 {
		return false, "Password must be less than 128 characters"
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return false, "Password must contain at least one uppercase letter"
	}
	if !hasLower {
		return false, "Password must contain at least one lowercase letter"
	}
	if !hasDigit {
		return false, "Password must contain at least one digit"
	}
	if !hasSpecial {
		return false, "Password must contain at least one special character"
	}

	return true, ""
}

func isValidUsername(username string) (bool, string) {
	if len(username) < 3 {
		return false, "Username must be at least 3 characters long"
	}

	if len(username) > 30 {
		return false, "Username must be less than 30 characters"
	}

	// Allow only alphanumeric characters, underscores, and hyphens
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !usernameRegex.MatchString(username) {
		return false, "Username can only contain letters, numbers, underscores, and hyphens"
	}

	// Must start with a letter or number
	if !unicode.IsLetter(rune(username[0])) && !unicode.IsDigit(rune(username[0])) {
		return false, "Username must start with a letter or number"
	}

	return true, ""
}

func sanitizeInput(input string) string {
	// Remove null bytes and control characters
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove other control characters except newlines and tabs (if needed)
	var result strings.Builder
	for _, r := range input {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			continue
		}
		result.WriteRune(r)
	}

	// Trim whitespace
	return strings.TrimSpace(result.String())
}

func main() {
	// Inicializar JWT secret key - CRÍTICO para seguridad
	initJWTSecret()

	// Inicializar cliente Django para autenticación híbrida
	initDjangoClient()

	// Inicializar usuarios con contraseñas hasheadas
	initializeUsers()

	// Iniciar rutina de limpieza de tokens expirados (cada 1 hora)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refreshTokenStore.cleanExpiredTokens()
				tokenBlacklist.cleanExpiredBlacklistedTokens()
				log.Printf("🧹 Cleaned expired refresh tokens and blacklisted tokens")
			}
		}
	}()

	r := gin.Default()

	// Security headers middleware
	r.Use(func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// CORS headers
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "healthy",
			"service": "auth-service",
			"version": "1.0.0",
		})
	})

	// Auth endpoints with rate limiting
	auth := r.Group("/auth")
	auth.Use(rateLimitMiddleware()) // Apply rate limiting to auth endpoints
	{
		auth.POST("/register", registerHandler)
		auth.POST("/login", loginHandler)
		auth.POST("/refresh", refreshHandler)
		auth.POST("/logout", jwtAuthMiddleware(), logoutHandler)
		auth.GET("/profile", jwtAuthMiddleware(), profileHandler)
		auth.PUT("/profile", jwtAuthMiddleware(), updateProfileHandler)
	}

	port := os.Getenv("AUTH_PORT")
	if port == "" {
		port = "8081"
	}

	fmt.Printf("🔐 Auth Service running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func registerHandler(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	// Sanitize inputs
	req.Username = sanitizeInput(req.Username)
	req.Email = sanitizeInput(req.Email)
	req.Password = sanitizeInput(req.Password)

	// Validate username
	if valid, msg := isValidUsername(req.Username); !valid {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   msg,
		})
		return
	}

	// Validate email format
	if !isValidEmail(req.Email) {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Invalid email format",
		})
		return
	}

	// Validate password strength
	if valid, msg := isValidPassword(req.Password); !valid {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   msg,
		})
		return
	}

	// Verificar si el usuario ya existe
	if _, exists := userStore.getUser(req.Email); exists {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Email already registered",
		})
		return
	}

	// Hash de la contraseña de forma segura
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	// Crear nuevo usuario
	newUser := &StoredUser{
		ID:             uint(len(userStore.users) + 1), // Simple ID generation
		Username:       req.Username,
		Email:          req.Email,
		HashedPassword: hashedPassword,
		Level:          1, // Nivel inicial para nuevos usuarios
		Credits:        100, // Créditos iniciales
	}

	// Agregar usuario al store
	userStore.addUser(newUser)

	// Determinar tipo de usuario usando el helper
	userType := getUserTypeFromStored(newUser)

	// Crear respuesta de éxito (sin contraseña)
	responseUser := &User{
		ID:       newUser.ID,
		Username: newUser.Username,
		Email:    newUser.Email,
		Level:    newUser.Level,
		Credits:  newUser.Credits,
		UserType: userType,
	}

	// Generar tokens JWT seguros
	accessToken, err := generateAccessToken(responseUser)
	if err != nil {
		log.Printf("Error generating access token: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	refreshToken, err := generateRefreshToken(responseUser)
	if err != nil {
		log.Printf("Error generating refresh token: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	// Obtener duración del token de acceso para esta respuesta
	config := TokenConfig[userType]
	expiresIn := int(config.AccessTokenDuration.Seconds())

	log.Printf("🆕 New user registered: %s (Type: %s)", req.Email, userType)

	c.JSON(201, LoginResponse{
		Success:      true,
		User:         responseUser,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	})
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	// Sanitize inputs
	req.Email = sanitizeInput(req.Email)
	req.Password = sanitizeInput(req.Password)

	// Validate email format
	if !isValidEmail(req.Email) {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Invalid email format",
		})
		return
	}

	// Basic password validation (not as strict for login)
	if len(req.Password) == 0 {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Password is required",
		})
		return
	}

	// PASO 1: Buscar usuario en el store local (SQLite)
	storedUser, exists := userStore.getUser(req.Email)

	// PASO 2: Si no existe localmente Y Django está habilitado, intentar con Django
	if !exists && djangoEnabled && djangoClient != nil {
		log.Printf("🔍 User %s not found locally, attempting Django authentication...", req.Email)

		// Autenticar con Django
		djangoUser, err := djangoClient.AuthenticateWithDjango(req.Email, req.Password)
		if err != nil {
			// Django authentication failed
			log.Printf("❌ Django authentication failed for %s: %v", req.Email, err)
			rateLimiter.recordAttempt(c.ClientIP(), false)
			c.JSON(401, LoginResponse{
				Success: false,
				Error:   "Invalid email or password",
			})
			return
		}

		// Django authentication successful - sync user to local store
		log.Printf("✅ Django user authenticated, syncing to local store: %s", req.Email)
		userStore.addUser(djangoUser)
		storedUser = djangoUser
		exists = true
	} else if !exists {
		// Usuario no encontrado localmente y Django no está habilitado
		rateLimiter.recordAttempt(c.ClientIP(), false)
		c.JSON(401, LoginResponse{
			Success: false,
			Error:   "Invalid email or password",
		})
		return
	}

	// PASO 3: Si el usuario existe localmente, verificar contraseña
	// Solo verificamos contraseña si es un usuario local (tiene hashedPassword)
	if storedUser.HashedPassword != "" {
		// Usuario local - verificar con bcrypt
		if !verifyPassword(storedUser.HashedPassword, req.Password) {
			rateLimiter.recordAttempt(c.ClientIP(), false)
			c.JSON(401, LoginResponse{
				Success: false,
				Error:   "Invalid email or password",
			})
			return
		}
	} else {
		// Usuario Django sincronizado - revalidar con Django API
		if djangoEnabled && djangoClient != nil {
			_, err := djangoClient.AuthenticateWithDjango(req.Email, req.Password)
			if err != nil {
				log.Printf("❌ Django revalidation failed for %s: %v", req.Email, err)
				rateLimiter.recordAttempt(c.ClientIP(), false)
				c.JSON(401, LoginResponse{
					Success: false,
					Error:   "Invalid email or password",
				})
				return
			}
			log.Printf("✅ Django user revalidated: %s", req.Email)
		} else {
			// Usuario Django pero API no disponible
			log.Printf("⚠️  Warning: Django user %s but Django API not available", req.Email)
			rateLimiter.recordAttempt(c.ClientIP(), false)
			c.JSON(503, LoginResponse{
				Success: false,
				Error:   "Authentication service temporarily unavailable",
			})
			return
		}
	}

	// Determinar tipo de usuario usando el helper
	userType := getUserTypeFromStored(storedUser)

	// Login exitoso - crear respuesta sin contraseña
	user := &User{
		ID:       storedUser.ID,
		Username: storedUser.Username,
		Email:    storedUser.Email,
		Level:    storedUser.Level,
		Credits:  storedUser.Credits,
		UserType: userType,
	}

	// Generar tokens JWT seguros
	accessToken, err := generateAccessToken(user)
	if err != nil {
		log.Printf("Error generating access token: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	refreshToken, err := generateRefreshToken(user)
	if err != nil {
		log.Printf("Error generating refresh token: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	// Obtener duración del token de acceso para esta respuesta
	config := TokenConfig[userType]
	expiresIn := int(config.AccessTokenDuration.Seconds())

	// Record successful login attempt
	rateLimiter.recordAttempt(c.ClientIP(), true)

	log.Printf("✅ User logged in: %s (Type: %s)", req.Email, userType)

	c.JSON(200, LoginResponse{
		Success:      true,
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	})
}

func refreshHandler(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, LoginResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	// Validar y parsear el refresh token
	claims, err := validateJWT(req.RefreshToken)
	if err != nil {
		c.JSON(401, LoginResponse{
			Success: false,
			Error:   "Invalid refresh token",
		})
		return
	}

	// Verificar que es un refresh token (subject debe empezar con "refresh:")
	if claims.Subject == "" || len(claims.Subject) < 8 || claims.Subject[:8] != "refresh:" {
		c.JSON(401, LoginResponse{
			Success: false,
			Error:   "Invalid token type",
		})
		return
	}

	// Validar el refresh token en el store (token rotation)
	entry, isValid := refreshTokenStore.validateRefreshToken(claims.ID)
	if !isValid {
		c.JSON(401, LoginResponse{
			Success: false,
			Error:   "Refresh token expired or already used",
		})
		return
	}

	// Verificar que el usuario del token coincide con el entry
	if entry.UserID != claims.UserID {
		c.JSON(401, LoginResponse{
			Success: false,
			Error:   "Token mismatch",
		})
		return
	}

	// Obtener información del usuario
	user := &User{
		ID:       claims.UserID,
		Username: claims.Username,
		Email:    claims.Email,
		Level:    claims.Level,
		UserType: claims.UserType,
	}

	// Generar nuevos tokens (token rotation)
	newAccessToken, err := generateAccessToken(user)
	if err != nil {
		log.Printf("Error generating new access token: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	newRefreshToken, err := generateRefreshToken(user)
	if err != nil {
		log.Printf("Error generating new refresh token: %v", err)
		c.JSON(500, LoginResponse{
			Success: false,
			Error:   "Internal server error",
		})
		return
	}

	// Obtener duración del token de acceso
	config := TokenConfig[claims.UserType]
	expiresIn := int(config.AccessTokenDuration.Seconds())

	log.Printf("🔄 Token refreshed for user: %s (Type: %s)", claims.Email, claims.UserType)

	c.JSON(200, LoginResponse{
		Success:      true,
		User:         user,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    expiresIn,
	})
}

func profileHandler(c *gin.Context) {
	// Obtener información del usuario autenticado desde el middleware JWT
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(500, gin.H{"error": "User ID not found in context"})
		return
	}

	email, exists := c.Get("email")
	if !exists {
		c.JSON(500, gin.H{"error": "Email not found in context"})
		return
	}

	userType, exists := c.Get("user_type")
	if !exists {
		c.JSON(500, gin.H{"error": "User type not found in context"})
		return
	}

	// En un sistema real, aquí buscaríamos la información completa del usuario en la base de datos
	// Para este ejemplo, simulamos la información del usuario basada en el email
	user := User{
		ID:       userID.(uint),
		Username: strings.Split(email.(string), "@")[0], // Usar parte del email como username
		Email:    email.(string),
		UserType: userType.(UserType),
		Level:    getDefaultLevel(userType.(UserType)),
		Credits:  getDefaultCredits(userType.(UserType)),
	}

	c.JSON(200, gin.H{
		"user": user,
	})
}

// Helper functions para obtener valores por defecto basados en el tipo de usuario
func getDefaultLevel(userType UserType) int {
	switch userType {
	case UserTypeFree:
		return 1
	case UserTypePro:
		return 5
	case UserTypeEnterprise:
		return 8
	case UserTypeAdmin:
		return 10
	default:
		return 1
	}
}

func getDefaultCredits(userType UserType) int {
	switch userType {
	case UserTypeFree:
		return 100
	case UserTypePro:
		return 1000
	case UserTypeEnterprise:
		return 5000
	case UserTypeAdmin:
		return 99999
	default:
		return 100
	}
}

func updateProfileHandler(c *gin.Context) {
	// TODO: Implementar actualización de perfil
	c.JSON(200, gin.H{
		"message": "Profile update endpoint",
		"status":  "not_implemented",
	})
}

// jwtAuthMiddleware valida el token JWT y verifica si está en la blacklist
func jwtAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Verificar formato Bearer token
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(401, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := tokenParts[1]

		// Parsear y validar el token
		token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Verificar el método de firma
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token: " + err.Error()})
			c.Abort()
			return
		}

		// Verificar si el token es válido
		if !token.Valid {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Obtener claims
		claims, ok := token.Claims.(*JWTClaims)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Verificar si el token está en la blacklist
		if tokenBlacklist.isTokenBlacklisted(claims.ID) {
			c.JSON(401, gin.H{"error": "Token has been revoked"})
			c.Abort()
			return
		}

		// Verificar expiración
		if time.Now().Unix() > claims.ExpiresAt.Unix() {
			c.JSON(401, gin.H{"error": "Token has expired"})
			c.Abort()
			return
		}

		// Guardar información del usuario en el contexto
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("user_type", claims.UserType)
		c.Set("token_id", claims.ID)

		c.Next()
	}
}

// logoutHandler maneja el logout seguro invalidando tokens
func logoutHandler(c *gin.Context) {
	// Obtener información del token desde el middleware
	tokenID, exists := c.Get("token_id")
	if !exists {
		c.JSON(500, gin.H{"error": "Token ID not found in context"})
		return
	}

	userIDInterface, exists := c.Get("user_id")
	if !exists {
		c.JSON(500, gin.H{"error": "User ID not found in context"})
		return
	}

	userID, ok := userIDInterface.(uint)
	if !ok {
		c.JSON(500, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Obtener el token del header para obtener la expiración
	authHeader := c.GetHeader("Authorization")
	tokenString := strings.Split(authHeader, " ")[1]

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to parse token"})
		return
	}

	claims := token.Claims.(*JWTClaims)

	// Agregar el token a la blacklist
	tokenBlacklist.blacklistToken(tokenID.(string), claims.ExpiresAt.Time, "user_logout")

	// Revocar todos los refresh tokens del usuario
	refreshTokenStore.revokeUserTokens(userID)

	c.JSON(200, gin.H{
		"message": "Successfully logged out",
		"status":  "success",
	})
}