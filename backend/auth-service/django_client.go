package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// DjangoAuthResponse estructura de respuesta de Django API
type DjangoAuthResponse struct {
	Success     bool   `json:"success"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	User        struct {
		ID         int    `json:"id"`
		Username   string `json:"username"`
		Email      string `json:"email"`
		Level      int    `json:"level"`
		Credits    int    `json:"credits"`
		Experience int    `json:"experience"`
		Team       string `json:"team"`
		Role       string `json:"role"`
		Status     string `json:"status"`
	} `json:"user"`
	Error string `json:"error"`
	Code  string `json:"code"`
}

// DjangoClient cliente HTTP para comunicación con Django API
type DjangoClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewDjangoClient crea una nueva instancia del cliente Django
func NewDjangoClient(baseURL string) *DjangoClient {
	return &DjangoClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// AuthenticateWithDjango autentica un usuario con el backend Django
func (dc *DjangoClient) AuthenticateWithDjango(email, password string) (*StoredUser, error) {
	// Construir payload
	payload := map[string]string{
		"email":    email,
		"password": password,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling payload: %w", err)
	}

	// Construir URL
	url := fmt.Sprintf("%s/auth/login/", dc.BaseURL)

	// Crear request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Ejecutar request
	log.Printf("🌐 Authenticating with Django API: %s", url)
	resp, err := dc.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to Django: %w", err)
	}
	defer resp.Body.Close()

	// Leer respuesta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Parsear respuesta
	var djangoResp DjangoAuthResponse
	if err := json.Unmarshal(body, &djangoResp); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Verificar éxito
	if !djangoResp.Success {
		// Mapear códigos de error de Django
		switch djangoResp.Code {
		case "AUTH_FAILED":
			return nil, fmt.Errorf("invalid credentials")
		case "ACCOUNT_BANNED":
			return nil, fmt.Errorf("account is banned")
		case "INVALID_DATA":
			return nil, fmt.Errorf("invalid request data")
		default:
			return nil, fmt.Errorf("authentication failed: %s", djangoResp.Error)
		}
	}

	// Convertir usuario de Django a StoredUser local
	storedUser := &StoredUser{
		ID:             uint(djangoResp.User.ID),
		Username:       djangoResp.User.Username,
		Email:          djangoResp.User.Email,
		Level:          djangoResp.User.Level,
		Credits:        djangoResp.User.Credits,
		HashedPassword: "", // No almacenamos la contraseña de usuarios Django
	}

	log.Printf("✅ Django authentication successful for user: %s (ID: %d, Level: %d)",
		storedUser.Email, storedUser.ID, storedUser.Level)

	return storedUser, nil
}

// VerifyDjangoToken verifica un token JWT de Django
func (dc *DjangoClient) VerifyDjangoToken(token string) (bool, error) {
	// Construir payload
	payload := map[string]string{
		"token": token,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("error marshaling payload: %w", err)
	}

	// Construir URL
	url := fmt.Sprintf("%s/auth/verify-token/", dc.BaseURL)

	// Crear request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return false, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Ejecutar request
	resp, err := dc.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Leer respuesta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response: %w", err)
	}

	// Parsear respuesta
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("error parsing response: %w", err)
	}

	// Verificar si el token es válido
	if valid, ok := result["valid"].(bool); ok {
		return valid, nil
	}

	return false, fmt.Errorf("invalid response format")
}
