# Plan de Integración de Autenticación Django-Desktop

## 📋 Objetivo
Permitir que usuarios registrados en synckz.com (Django/PostgreSQL) puedan iniciar sesión en la aplicación de escritorio (Go/SQLite) sin necesidad de crear una cuenta separada.

## 🔍 Análisis del Estado Actual

### Django (synckz.com)
- **Framework:** Django 5.2
- **Base de datos:** PostgreSQL (huntersdb)
- **Modelo de usuario:** `registration.CustomUser`
  ```python
  class CustomUser(AbstractUser):
      email = models.EmailField(unique=True)  # Login principal
      username = models.CharField(...)
      password = models.CharField(...)  # Hasheado con PBKDF2

      # Campos adicionales
      team = models.CharField(max_length=255)
      role = models.CharField(max_length=50)
      status = models.CharField(...)  # 'active' | 'banned'
      level = models.IntegerField(default=1)
      credits = models.IntegerField(default=0)
      experience = models.IntegerField(default=0)
  ```

- **Autenticación actual:** Session-based (Django sessions)
- **No tiene API REST** para autenticación externa

### Desktop App (Synckz Desktop)
- **Backend:** Go microservices (auth-service :8081)
- **Base de datos:** SQLite local (auth.db)
- **Modelo de usuario:**
  ```go
  type StoredUser struct {
      ID             int
      Username       string
      Email          string
      HashedPassword string
      Level          int
      Credits        int
  }
  ```
- **Autenticación actual:** JWT local

### 🔑 Diferencias Críticas
| Aspecto | Django | Desktop App |
|---------|--------|------------|
| **Auth Type** | Session-based | JWT |
| **Password Hash** | PBKDF2_SHA256 | Bcrypt |
| **Database** | PostgreSQL | SQLite |
| **Users** | Production users | Demo users (admin, demo) |

## 🎯 Estrategia de Integración: Autenticación Híbrida

### Arquitectura Propuesta

```
┌─────────────────────────────────────────────────────────────────┐
│                      DESKTOP APPLICATION                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐           ┌──────────────────────────────┐   │
│  │   Frontend  │  Login    │   Go Auth Service :8081      │   │
│  │  React UI   │──────────▶│                              │   │
│  │  :5177      │           │  ┌────────────────────────┐  │   │
│  └─────────────┘           │  │ 1. Check SQLite Local  │  │   │
│                            │  │    (Demo users)         │  │   │
│                            │  └────────────────────────┘  │   │
│                            │           ▼                   │   │
│                            │  ┌────────────────────────┐  │   │
│                            │  │ 2. If not found:       │  │   │
│                            │  │    Check Django API    │  │   │
│                            │  │    (Production users)  │  │   │
│                            │  └────────────────────────┘  │   │
│                            │           │                   │   │
│                            │           ▼                   │   │
│                            │  ┌────────────────────────┐  │   │
│                            │  │ 3. Sync to SQLite      │  │   │
│                            │  │    (Cache user data)   │  │   │
│                            │  └────────────────────────┘  │   │
│                            │           │                   │   │
│                            │           ▼                   │   │
│                            │  ┌────────────────────────┐  │   │
│                            │  │ 4. Generate JWT        │  │   │
│                            │  └────────────────────────┘  │   │
│                            └──────────────────────────────┘   │
│                                       │                        │
│                                       │ HTTP REST API          │
│                                       ▼                        │
└───────────────────────────────────────┼────────────────────────┘
                                        │
                                        │ HTTPS
                                        │
┌───────────────────────────────────────┼────────────────────────┐
│                                       ▼                        │
│               DJANGO BACKEND (synckz.com)                      │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐     │
│  │       New API Endpoints (registration/api_views.py)  │     │
│  │                                                       │     │
│  │  POST /api/v1/desktop/auth/login                     │     │
│  │  POST /api/v1/desktop/auth/verify-token              │     │
│  │  GET  /api/v1/desktop/auth/user-profile              │     │
│  │  POST /api/v1/desktop/auth/logout                    │     │
│  └──────────────────────────────────────────────────────┘     │
│                          │                                      │
│                          ▼                                      │
│  ┌──────────────────────────────────────────────────────┐     │
│  │          PostgreSQL Database (huntersdb)             │     │
│  │                                                       │     │
│  │  registration_customuser:                            │     │
│  │  - id, username, email, password (PBKDF2)            │     │
│  │  - level, credits, experience, team, role, status    │     │
│  └──────────────────────────────────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 📝 Plan de Implementación

### Fase 1: Crear API REST en Django ✅

**Archivos a crear en el proyecto Django:**

1. **`registration/api_views.py`** - Endpoints REST para desktop app
2. **`registration/api_urls.py`** - URLs de la API
3. **`registration/serializers.py`** - Serializadores de datos
4. **`registration/authentication.py`** - Clase de autenticación JWT para DRF

**Endpoints a implementar:**

```python
POST /api/v1/desktop/auth/login
Request:  {"email": "user@synckz.com", "password": "password123"}
Response: {
    "success": true,
    "access_token": "jwt_token_here",
    "user": {
        "id": 1,
        "username": "user123",
        "email": "user@synckz.com",
        "level": 5,
        "credits": 1000,
        "experience": 4500,
        "team": "Team Alpha",
        "role": "Normal User",
        "status": "active"
    }
}

GET /api/v1/desktop/auth/user-profile
Headers: Authorization: Bearer <token>
Response: { /* user data */ }

POST /api/v1/desktop/auth/verify-token
Request:  {"token": "jwt_token_here"}
Response: {"valid": true, "user_id": 1}
```

### Fase 2: Modificar Go Auth Service ✅

**Archivo:** `backend/auth-service/main.go`

**Cambios a realizar:**

1. **Agregar configuración de Django API:**
   ```go
   var (
       djangoAPIURL = os.Getenv("DJANGO_API_URL")  // "https://synckz.com/api/v1/desktop"
       djangoEnabled = os.Getenv("DJANGO_AUTH_ENABLED") == "true"
   )
   ```

2. **Modificar función de login:**
   ```go
   func handleLogin(c *gin.Context) {
       var creds LoginCredentials
       c.BindJSON(&creds)

       // 1. Intentar login local (SQLite)
       user, err := authenticateLocal(creds.Email, creds.Password)

       if err != nil && djangoEnabled {
           // 2. Intentar login con Django
           user, err = authenticateDjango(creds.Email, creds.Password)

           if err == nil {
               // 3. Sincronizar usuario a SQLite
               syncUserToLocal(user)
           }
       }

       if err != nil {
           c.JSON(401, gin.H{"error": "Invalid credentials"})
           return
       }

       // 4. Generar JWT local
       token := generateJWT(user)
       c.JSON(200, LoginResponse{...})
   }
   ```

3. **Nueva función `authenticateDjango`:**
   ```go
   func authenticateDjango(email, password string) (*StoredUser, error) {
       // HTTP POST to Django API
       resp, err := http.Post(
           djangoAPIURL + "/auth/login",
           "application/json",
           bytes.NewBuffer(jsonData),
       )

       // Parse response and return user
   }
   ```

### Fase 3: Sincronización de Usuarios ✅

**Estrategia:**
- **Primera vez:** Usuario se autentica con Django → se crea en SQLite local
- **Subsiguientes:** Autenticación local (más rápida)
- **Actualización:** Sincronización periódica opcional

**Tabla SQLite actualizada:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    django_id INTEGER,           -- NEW: ID del usuario en Django
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    hashed_password TEXT,
    level INTEGER DEFAULT 1,
    credits INTEGER DEFAULT 0,
    experience INTEGER DEFAULT 0,
    team TEXT,
    role TEXT,
    status TEXT DEFAULT 'active',
    last_sync DATETIME,          -- NEW: Última sincronización con Django
    is_local BOOLEAN DEFAULT 0,  -- NEW: true = demo user, false = Django user
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Fase 4: Actualizar Frontend ✅

**Archivo:** `frontend/src/services/authService.ts`

**Cambios mínimos** (la API Go ya maneja la integración):

```typescript
// No se requieren cambios significativos
// El frontend sigue usando el mismo endpoint local
async login(credentials: LoginCredentials): Promise<LoginResponse> {
  const response = await this.makeRequest<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
  return response;
}

// Opcional: Agregar indicador de origen del usuario
interface User {
  id: number;
  username: string;
  email: string;
  level: number;
  credits: number;
  is_synced: boolean;  // true si viene de Django
}
```

## 🔒 Consideraciones de Seguridad

### 1. Manejo de Contraseñas
- **Django:** Usa PBKDF2_SHA256 (muy seguro)
- **Go local:** Usa Bcrypt (muy seguro)
- **Problema:** No podemos validar password de Django localmente (hashes incompatibles)
- **Solución:** Siempre validar con Django API para usuarios Django

### 2. Almacenamiento Local
```go
type StoredUser struct {
    DjangoID       int    // ID en Django
    Email          string
    HashedPassword string // Solo para usuarios locales (demo)
    // NO almacenar password de usuarios Django
    IsLocal        bool   // true = demo, false = Django
}
```

**Para usuarios Django:**
- NO almacenar el password hasheado
- Revalidar con Django API periódicamente
- Cache solo datos públicos (username, level, credits)

### 3. JWT Tokens
- **Generados por:** Go auth-service
- **Firmados con:** JWT_SECRET local
- **Válidos para:** Sesión local de la app
- **NO reemplaza:** Sesión de Django (son independientes)

### 4. Rate Limiting
```go
// Limitar intentos de login
var loginAttempts = make(map[string]int)

func checkRateLimit(email string) bool {
    if loginAttempts[email] > 5 {
        return false
    }
    return true
}
```

## 📊 Flujo de Autenticación Completo

### Escenario 1: Usuario Django (primera vez)

```
1. Usuario ingresa email: owner@synckz.com, password: ******
   ↓
2. Frontend → POST localhost:8081/auth/login
   ↓
3. Go auth-service:
   - Busca en SQLite local → NO ENCONTRADO
   - djangoEnabled = true → Intenta Django
   ↓
4. Go → POST https://synckz.com/api/v1/desktop/auth/login
   Request: {"email": "owner@synckz.com", "password": "******"}
   ↓
5. Django valida credenciales con PostgreSQL
   Response: {
     "success": true,
     "user": {
       "id": 3,
       "username": "owner",
       "email": "owner@synckz.com",
       "level": 10,
       "credits": 50000,
       ...
     }
   }
   ↓
6. Go auth-service:
   - Guarda usuario en SQLite (sin password)
   - Genera JWT local
   ↓
7. Response al Frontend:
   {
     "success": true,
     "token": "eyJhbGciOi...",
     "user": {...},
     "is_synced": true
   }
   ↓
8. Frontend almacena token y redirige a dashboard
```

### Escenario 2: Usuario local (demo)

```
1. Usuario ingresa email: admin@synckz.com, password: admin123
   ↓
2. Frontend → POST localhost:8081/auth/login
   ↓
3. Go auth-service:
   - Busca en SQLite local → ENCONTRADO (is_local = true)
   - Valida password con Bcrypt → OK
   ↓
4. Genera JWT local y responde
   (Sin llamar a Django)
```

### Escenario 3: Usuario Django (ya sincronizado)

```
1. Usuario ingresa email: owner@synckz.com, password: ******
   ↓
2. Frontend → POST localhost:8081/auth/login
   ↓
3. Go auth-service:
   - Busca en SQLite local → ENCONTRADO (is_local = false)
   - Como es usuario Django, valida con API
   ↓
4. Go → POST https://synckz.com/api/v1/desktop/auth/login
   ↓
5. Django valida y responde
   ↓
6. Go actualiza datos en SQLite (level, credits, etc.)
   ↓
7. Genera JWT y responde
```

## 🚀 Orden de Implementación

### Paso 1: Preparar Django (en producción)
```bash
# En el servidor de producción (synckz.com)
cd /path/to/synckz/
pip install djangorestframework djangorestframework-simplejwt
```

Archivos a crear:
- `registration/api_views.py`
- `registration/api_urls.py`
- `registration/serializers.py`
- Actualizar `registration/urls.py`
- Actualizar `huntersbook/settings.py`

### Paso 2: Configurar Go Auth Service
```bash
# En el proyecto desktop
cd backend/auth-service/
```

Modificar:
- `main.go` - Agregar lógica de autenticación híbrida
- Crear `django_client.go` - Cliente HTTP para Django API
- Actualizar esquema SQLite

### Paso 3: Probar Integración
```bash
# 1. Iniciar servicios locales
cd backend/auth-service
DJANGO_API_URL="https://synckz.com/api/v1/desktop" \
DJANGO_AUTH_ENABLED="true" \
JWT_SECRET="shared_jwt_secret_for_testing_123" \
AUTH_PORT=8081 go run main.go

# 2. Iniciar frontend
cd frontend
npm run dev

# 3. Probar login con usuario Django
# Email: owner@synckz.com
# Password: [password de producción]
```

## ✅ Validación de la Integración

### Tests Manuales

1. **Login con usuario local (demo):**
   - Email: `admin@synckz.com`
   - Password: `admin123`
   - ✅ Debe funcionar sin conexión a Django

2. **Login con usuario Django:**
   - Email: `owner@synckz.com`
   - Password: [password real]
   - ✅ Debe validar con Django y sincronizar

3. **Login offline después de sincronización:**
   - Desactivar `DJANGO_AUTH_ENABLED`
   - Intentar login con usuario Django
   - ❌ Debe fallar (sin password local)
   - ✅ Actualizar para permitir cache de sesión

## 🔧 Variables de Entorno

### Go Auth Service
```bash
DJANGO_API_URL="https://synckz.com/api/v1/desktop"
DJANGO_AUTH_ENABLED="true"
DJANGO_API_KEY="secret_key_for_api_auth"  # Opcional
JWT_SECRET="shared_jwt_secret_for_testing_123"
AUTH_PORT=8081
```

### Django (.env.prod)
```bash
# Ya existentes...

# Nuevas
DESKTOP_APP_ALLOWED_ORIGINS="http://localhost:5177,http://127.0.0.1:5177"
DESKTOP_JWT_SECRET="shared_jwt_secret_for_testing_123"
DESKTOP_JWT_EXPIRATION=86400  # 24 horas
```

## 📈 Próximos Pasos (Opcionales)

### Mejoras Futuras

1. **Sincronización bidireccional:**
   - Cambios en el desktop → Sync a Django
   - Ejemplo: Actualizar level, credits desde la app

2. **OAuth2 Flow:**
   - Implementar flujo OAuth2 completo
   - Refresh tokens
   - Revocación de tokens

3. **Sincronización de datos:**
   - Walkthroughs creados en desktop → Publicar en synckz.com
   - Subdomains encontrados → Compartir con comunidad

4. **Modo offline mejorado:**
   - Cache de credenciales (encriptado)
   - Sincronización automática al reconectar

## 🎯 Resultado Final

**Comportamiento esperado:**

- ✅ Usuario se registra en synckz.com
- ✅ Descarga Synckz Desktop
- ✅ Inicia sesión con sus credenciales de synckz.com
- ✅ La app sincroniza su perfil (level, credits, team)
- ✅ Puede trabajar offline con datos locales
- ✅ Puede compartir datos con la comunidad (futuro)

**Sin duplicación de cuentas:**
- ❌ No necesita crear cuenta separada para desktop
- ✅ Una sola identidad: synckz.com

---

**Autor:** Claude Code
**Fecha:** 2025-01-07
**Versión:** 1.0
**Estado:** Plan completo - Listo para implementación
