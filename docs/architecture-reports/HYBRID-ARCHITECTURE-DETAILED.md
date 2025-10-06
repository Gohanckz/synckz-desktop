# 🏗️ Arquitectura Híbrida Synckz - Diagramas Detallados

## 📊 Diagrama 1: Arquitectura General del Sistema

```mermaid
graph TB
    subgraph "USUARIO"
        U[👤 Usuario]
    end

    subgraph "SYNCKZ DESKTOP APP - LOCAL"
        subgraph "Frontend - React/TypeScript"
            UI[🎨 UI Components]
            AUTH_UI[🔐 Auth UI]
            SYNC_UI[🔄 Sync Panel]
            WORKSPACE_UI[📁 Workspace UI]
            WALKTHROUGH_UI[📚 Walkthrough Editor]
            SUBDOMAIN_UI[🌐 Subdomain Scanner]
        end

        subgraph "Services Layer"
            LOCAL_AUTH[Local Auth Service]
            DJANGO_AUTH[Django Auth Service]
            SYNC_SERVICE[Sync Service]
            WORKSPACE_SERVICE[Workspace Service]
            SUBDOMAIN_SERVICE[Subdomain Service]
            WALKTHROUGH_SERVICE[Walkthrough Service]
        end

        subgraph "Local Storage - SQLite"
            LOCAL_DB[(SQLite DB)]
            LOCAL_USERS[Users Table]
            LOCAL_WORKSPACES[Workspaces]
            LOCAL_SUBDOMAINS[Subdomains]
            LOCAL_WALKTHROUGHS[Walkthroughs]
            LOCAL_CREDENTIALS[Credentials]
            SYNC_STATUS[Sync Status]
        end

        subgraph "Go Microservices - Backend Local"
            GO_AUTH[Go Auth Service :8081]
            GO_SUBDOMAIN[Go Subdomain Service :8082]
            GO_DORK[Go Dork Service :8083]
            GO_PORT[Go Port Scanner :8080]
            GO_METHODOLOGY[Go Methodology :8085]
            GO_BOARD[Go Board Service :8086]
            GO_WALKTHROUGH[Go Walkthrough :8087]
            GO_WORKSPACE[Go Workspace :8088]
            GO_CREDENTIAL[Go Credential :8089]
            GO_WORDLIST[Go Wordlist :8090]
        end
    end

    subgraph "INTERNET"
        INTERNET{☁️ Internet Connection}
    end

    subgraph "SYNCKZ.COM - DJANGO BACKEND"
        subgraph "Django API Layer"
            DJANGO_API[🌐 Django REST API]
            DJANGO_AUTH_EP[/api/auth/login/]
            DJANGO_PROFILE_EP[/api/user/profile/]
            DJANGO_WALKTHROUGH_EP[/api/walkthroughs/]
            DJANGO_SYNC_EP[/api/sync/]
            DJANGO_MARKETPLACE_EP[/api/marketplace/]
        end

        subgraph "Django Services"
            DJANGO_AUTH_SRV[Authentication Service]
            DJANGO_USER_SRV[User Service]
            DJANGO_SOCIAL_SRV[Social Service]
            DJANGO_MARKETPLACE_SRV[Marketplace Service]
        end

        subgraph "PostgreSQL Database"
            POSTGRES_DB[(PostgreSQL)]
            DJANGO_USERS[CustomUser]
            DJANGO_WALKTHROUGHS[Published Walkthroughs]
            DJANGO_COMMENTS[Comments]
            DJANGO_MARKETPLACE[Marketplace Items]
            DJANGO_TEAMS[Teams]
        end

        subgraph "Static Files"
            MEDIA[Media Files]
            STATIC[Static Assets]
        end
    end

    subgraph "WEB USERS"
        WEB_USER[🌐 Web Browser Users]
    end

    %% User interactions
    U -->|Usa app localmente| UI
    U -->|Opcional: Connect| SYNC_UI

    %% UI to Services
    UI --> LOCAL_AUTH
    UI --> WORKSPACE_SERVICE
    UI --> SUBDOMAIN_SERVICE
    UI --> WALKTHROUGH_SERVICE

    AUTH_UI --> LOCAL_AUTH
    AUTH_UI --> DJANGO_AUTH
    SYNC_UI --> SYNC_SERVICE

    %% Services to Go Microservices
    LOCAL_AUTH --> GO_AUTH
    WORKSPACE_SERVICE --> GO_WORKSPACE
    SUBDOMAIN_SERVICE --> GO_SUBDOMAIN
    WALKTHROUGH_SERVICE --> GO_WALKTHROUGH

    %% Go Services to Local DB
    GO_AUTH --> LOCAL_DB
    GO_WORKSPACE --> LOCAL_DB
    GO_SUBDOMAIN --> LOCAL_DB
    GO_WALKTHROUGH --> LOCAL_DB
    GO_CREDENTIAL --> LOCAL_DB
    GO_WORDLIST --> LOCAL_DB

    %% Local DB Tables
    LOCAL_DB --> LOCAL_USERS
    LOCAL_DB --> LOCAL_WORKSPACES
    LOCAL_DB --> LOCAL_SUBDOMAINS
    LOCAL_DB --> LOCAL_WALKTHROUGHS
    LOCAL_DB --> LOCAL_CREDENTIALS
    LOCAL_DB --> SYNC_STATUS

    %% Sync Service
    SYNC_SERVICE -.->|Opcional| INTERNET
    INTERNET -.-> DJANGO_API

    %% Django Auth
    DJANGO_AUTH -->|JWT Token| DJANGO_API
    DJANGO_API --> DJANGO_AUTH_EP
    DJANGO_API --> DJANGO_PROFILE_EP
    DJANGO_API --> DJANGO_WALKTHROUGH_EP
    DJANGO_API --> DJANGO_SYNC_EP
    DJANGO_API --> DJANGO_MARKETPLACE_EP

    %% Django Services
    DJANGO_AUTH_EP --> DJANGO_AUTH_SRV
    DJANGO_PROFILE_EP --> DJANGO_USER_SRV
    DJANGO_WALKTHROUGH_EP --> DJANGO_SOCIAL_SRV
    DJANGO_MARKETPLACE_EP --> DJANGO_MARKETPLACE_SRV

    %% Django to PostgreSQL
    DJANGO_AUTH_SRV --> POSTGRES_DB
    DJANGO_USER_SRV --> POSTGRES_DB
    DJANGO_SOCIAL_SRV --> POSTGRES_DB
    DJANGO_MARKETPLACE_SRV --> POSTGRES_DB

    POSTGRES_DB --> DJANGO_USERS
    POSTGRES_DB --> DJANGO_WALKTHROUGHS
    POSTGRES_DB --> DJANGO_COMMENTS
    POSTGRES_DB --> DJANGO_MARKETPLACE

    %% Web users
    WEB_USER -->|Browse community| DJANGO_API

    style U fill:#4CAF50
    style INTERNET fill:#2196F3
    style LOCAL_DB fill:#FFC107
    style POSTGRES_DB fill:#9C27B0
    style DJANGO_API fill:#FF5722
```

---

## 🔄 Diagrama 2: Flujo de Autenticación Dual

```mermaid
sequenceDiagram
    participant User as 👤 Usuario
    participant UI as 🎨 Desktop UI
    participant LocalAuth as 🔐 Local Auth Service
    participant GoAuth as Go Auth :8081
    participant LocalDB as 💾 SQLite Local
    participant DjangoAuth as ☁️ Django Auth Service
    participant SyncService as 🔄 Sync Service
    participant DjangoAPI as 🌐 Django API
    participant PostgreSQL as 🗄️ PostgreSQL

    rect rgb(200, 220, 240)
        Note over User,LocalDB: MODO 1: Autenticación Local (Offline)
        User->>UI: 1. Abre la app (primera vez)
        UI->>LocalAuth: 2. Check existing session
        LocalAuth->>LocalDB: 3. Query local users
        LocalDB-->>LocalAuth: 4. No users found
        UI->>User: 5. Show "Create Local Account"
        User->>UI: 6. Enter username/password
        UI->>LocalAuth: 7. createLocalUser(credentials)
        LocalAuth->>GoAuth: 8. POST /auth/register
        GoAuth->>LocalDB: 9. Hash password + Store user
        LocalDB-->>GoAuth: 10. User created (id: 1)
        GoAuth-->>LocalAuth: 11. JWT token (local)
        LocalAuth->>UI: 12. User logged in ✅
        UI->>User: 13. Show Dashboard (100% local)
    end

    rect rgb(220, 240, 200)
        Note over User,PostgreSQL: MODO 2: Login con Django (Online - Opcional)
        User->>UI: 14. Click "Connect to Synckz.com"
        UI->>SyncService: 15. showDjangoLogin()
        SyncService->>User: 16. Show Django login modal
        User->>SyncService: 17. Enter email/password
        SyncService->>DjangoAPI: 18. POST /api/auth/login/
        DjangoAPI->>DjangoAuth: 19. Authenticate user
        DjangoAuth->>PostgreSQL: 20. Query CustomUser
        PostgreSQL-->>DjangoAuth: 21. User found + verified
        DjangoAuth->>DjangoAPI: 22. Generate JWT token
        DjangoAPI-->>SyncService: 23. {access_token, user_data}
        SyncService->>LocalDB: 24. Store Django token + user_id mapping
        SyncService->>UI: 25. Update sync status: "Connected ✅"
        UI->>User: 26. Show sync options
    end

    rect rgb(240, 220, 200)
        Note over User,PostgreSQL: MODO 3: Dual Mode (Híbrido)
        User->>UI: 27. Working with local data
        UI->>LocalDB: 28. Save subdomain scan results
        LocalDB-->>UI: 29. Data saved locally ✅
        User->>UI: 30. Click "Publish to Community"
        UI->>SyncService: 31. publishWalkthrough(id)
        SyncService->>LocalDB: 32. Check Django connection
        LocalDB-->>SyncService: 33. Token valid, user_id mapped
        SyncService->>DjangoAPI: 34. POST /api/walkthroughs/ + Bearer token
        DjangoAPI->>PostgreSQL: 35. Insert walkthrough
        PostgreSQL-->>DjangoAPI: 36. Created (django_id: 123)
        DjangoAPI-->>SyncService: 37. {id: 123, published: true}
        SyncService->>LocalDB: 38. Update sync_status + django_id
        LocalDB-->>SyncService: 39. Updated ✅
        SyncService->>UI: 40. "Published to community! 🎉"
        UI->>User: 41. Show success + community link
    end
```

---

## 🗄️ Diagrama 3: Estructura de Bases de Datos

```mermaid
erDiagram
    %% ============ LOCAL DATABASE (SQLite) ============
    LOCAL_USER {
        int id PK
        string username
        string email
        string hashed_password
        int level
        int credits
        string user_type
        datetime created_at
        int django_user_id FK "NULL si no está sincronizado"
        string django_access_token "NULL si no conectado"
        string django_refresh_token
    }

    LOCAL_WORKSPACE {
        int id PK
        int user_id FK
        string name
        string description
        string target_domain
        datetime created_at
        string sync_status "pending|synced|local_only"
        int django_workspace_id "NULL si no sincronizado"
    }

    LOCAL_SUBDOMAIN {
        int id PK
        int workspace_id FK
        string subdomain
        string ip_address
        int status_code
        string title
        string technologies
        datetime discovered_at
        string sync_status "local_only|shared|pending"
        int django_subdomain_id
    }

    LOCAL_WALKTHROUGH {
        int id PK
        int user_id FK
        string title
        text content_markdown
        string difficulty
        string tags
        datetime created_at
        datetime updated_at
        string status "draft|published|archived"
        string sync_status "local_only|published|pending"
        int django_walkthrough_id
    }

    LOCAL_CREDENTIAL {
        int id PK
        int workspace_id FK
        string service_name
        string username
        string encrypted_password
        string url
        datetime created_at
        boolean shared "false = never sync"
    }

    LOCAL_PORT_SCAN {
        int id PK
        int workspace_id FK
        string target_ip
        int port
        string service
        string version
        datetime scanned_at
    }

    LOCAL_SYNC_LOG {
        int id PK
        int user_id FK
        string resource_type
        int resource_id
        string action "push|pull"
        datetime synced_at
        boolean success
        text error_message
    }

    %% ============ DJANGO DATABASE (PostgreSQL) ============
    DJANGO_CUSTOMUSER {
        int id PK
        string username
        string email UK
        string password
        string first_name
        string last_name
        int level
        int credits
        string role
        string status
        string team
        boolean is_staff
        boolean is_superuser
        boolean is_active
        datetime date_joined
        datetime last_login
        datetime last_connection
        string profile_picture
    }

    DJANGO_WALKTHROUGH {
        int id PK
        int author_id FK
        string title
        text content
        string difficulty
        string tags
        int views
        int claps
        datetime published_at
        datetime updated_at
        boolean is_featured
        string status
    }

    DJANGO_COMMENT {
        int id PK
        int walkthrough_id FK
        int user_id FK
        text content
        int claps
        datetime created_at
        int parent_comment_id
    }

    DJANGO_MARKETPLACE_ITEM {
        int id PK
        int seller_id FK
        string item_type "subdomain|wordlist|methodology"
        string title
        text description
        int price_credits
        json data
        datetime listed_at
        boolean is_sold
    }

    DJANGO_TEAM {
        int id PK
        string name
        string description
        int master_id FK
        datetime created_at
    }

    DJANGO_TEAM_MEMBERSHIP {
        int id PK
        int team_id FK
        int user_id FK
        string position "master|member"
        datetime joined_at
    }

    DJANGO_SYNC_TOKEN {
        int id PK
        int user_id FK
        string resource_type
        string last_sync_token
        datetime last_synced_at
    }

    %% ============ RELACIONES LOCALES ============
    LOCAL_USER ||--o{ LOCAL_WORKSPACE : "owns"
    LOCAL_USER ||--o{ LOCAL_WALKTHROUGH : "creates"
    LOCAL_WORKSPACE ||--o{ LOCAL_SUBDOMAIN : "contains"
    LOCAL_WORKSPACE ||--o{ LOCAL_CREDENTIAL : "stores"
    LOCAL_WORKSPACE ||--o{ LOCAL_PORT_SCAN : "has"
    LOCAL_USER ||--o{ LOCAL_SYNC_LOG : "performs"

    %% ============ RELACIONES DJANGO ============
    DJANGO_CUSTOMUSER ||--o{ DJANGO_WALKTHROUGH : "authors"
    DJANGO_CUSTOMUSER ||--o{ DJANGO_COMMENT : "writes"
    DJANGO_CUSTOMUSER ||--o{ DJANGO_MARKETPLACE_ITEM : "sells"
    DJANGO_CUSTOMUSER ||--o{ DJANGO_TEAM_MEMBERSHIP : "joins"
    DJANGO_WALKTHROUGH ||--o{ DJANGO_COMMENT : "has"
    DJANGO_TEAM ||--o{ DJANGO_TEAM_MEMBERSHIP : "contains"
    DJANGO_CUSTOMUSER ||--o{ DJANGO_SYNC_TOKEN : "has"

    %% ============ SINCRONIZACIÓN CROSS-DB ============
    LOCAL_USER }o--|| DJANGO_CUSTOMUSER : "syncs via django_user_id"
    LOCAL_WALKTHROUGH }o--|| DJANGO_WALKTHROUGH : "syncs via django_walkthrough_id"
```

---

## 🔄 Diagrama 4: Flujo de Sincronización de Walkthroughs

```mermaid
stateDiagram-v2
    [*] --> LocalDraft: User creates walkthrough

    state "LOCAL ONLY MODE" as LocalMode {
        LocalDraft --> Editing: User edits content
        Editing --> LocalDraft: Auto-save to SQLite
        Editing --> PreviewLocal: User previews
        PreviewLocal --> Editing: Continue editing
    }

    state "DECISION POINT" as Decision {
        state "Check Connection" as CheckConn
        LocalDraft --> CheckConn: User clicks "Publish"
        CheckConn --> NoDjangoAuth: No Django token
        CheckConn --> HasDjangoAuth: Token exists

        NoDjangoAuth --> ShowDjangoLogin: Prompt login
        ShowDjangoLogin --> DjangoLoginFlow: User enters credentials
        DjangoLoginFlow --> TokenReceived: Login success
        DjangoLoginFlow --> LoginFailed: Login failed
        LoginFailed --> LocalDraft: Remain local

        TokenReceived --> HasDjangoAuth: Store token
    }

    state "PUBLISHING PROCESS" as Publishing {
        HasDjangoAuth --> ValidateContent: Check required fields
        ValidateContent --> ContentInvalid: Missing data
        ContentInvalid --> Editing: Show errors

        ValidateContent --> ContentValid: All fields OK
        ContentValid --> UploadingToDjango: POST to /api/walkthroughs/

        UploadingToDjango --> UploadSuccess: 201 Created
        UploadingToDjango --> UploadFailed: Network/Auth error

        UploadFailed --> RetryQueue: Add to sync queue
        RetryQueue --> LocalDraft: Will retry later

        UploadSuccess --> UpdateLocalRecord: Store django_id + sync_status
        UpdateLocalRecord --> Published: Mark as published
    }

    state "PUBLISHED STATE" as PublishedState {
        Published --> CommunityVisible: Live on synckz.com
        CommunityVisible --> ReceivingComments: Users comment
        CommunityVisible --> ReceivingClaps: Users clap

        ReceivingComments --> PullComments: Sync service pulls
        PullComments --> UpdateLocalCache: Store in SQLite

        Published --> EditPublished: User edits locally
        EditPublished --> ConflictCheck: Check for conflicts
        ConflictCheck --> NoConflict: No web changes
        NoConflict --> PushUpdate: PUT to /api/walkthroughs/{id}/
        PushUpdate --> Published: Updated both sides

        ConflictCheck --> HasConflict: Web has changes
        HasConflict --> ShowConflictUI: Let user resolve
        ShowConflictUI --> MergeChanges: User merges
        MergeChanges --> Published: Conflict resolved
    }

    Published --> Unpublish: User clicks "Remove from community"
    Unpublish --> LocalDraft: Reverted to local-only

    Published --> [*]: User deletes (both local and Django)
```

---

## 🏢 Diagrama 5: Arquitectura de Microservicios Go

```mermaid
graph LR
    subgraph "FRONTEND - React/TypeScript :5177"
        UI[UI Layer]
        SERVICES[Service Layer]
    end

    subgraph "GO MICROSERVICES - Local Backend"
        subgraph "Authentication"
            GO_AUTH[Auth Service :8081]
            GO_AUTH_DB[(SQLite: users)]
        end

        subgraph "Workspace Management"
            GO_WORKSPACE[Workspace Service :8088]
            GO_WORKSPACE_DB[(SQLite: workspaces)]
        end

        subgraph "Reconnaissance"
            GO_SUBDOMAIN[Subdomain Service :8082]
            GO_PORT[Port Scanner :8080]
            GO_SUBDOMAIN_DB[(SQLite: subdomains)]
            GO_PORT_DB[(SQLite: port_scans)]
        end

        subgraph "OSINT Tools"
            GO_DORK[Dork Service :8083]
            GO_DORK_DB[(SQLite: dorks)]
        end

        subgraph "Knowledge Base"
            GO_METHODOLOGY[Methodology Service :8085]
            GO_WALKTHROUGH[Walkthrough Service :8087]
            GO_WORDLIST[Wordlist Service :8090]
            GO_METHOD_DB[(SQLite: methodologies)]
            GO_WALK_DB[(SQLite: walkthroughs)]
            GO_WORD_DB[(SQLite: wordlists)]
        end

        subgraph "Project Management"
            GO_BOARD[Board Service :8086]
            GO_CREDENTIAL[Credential Service :8089]
            GO_BOARD_DB[(SQLite: boards)]
            GO_CRED_DB[(SQLite: credentials)]
        end
    end

    subgraph "SHARED RESOURCES"
        SHARED_JWT[Shared JWT Secret]
        SHARED_CONFIG[Shared Config]
    end

    %% Frontend connections
    SERVICES -->|HTTP :8081| GO_AUTH
    SERVICES -->|HTTP :8088| GO_WORKSPACE
    SERVICES -->|HTTP :8082| GO_SUBDOMAIN
    SERVICES -->|HTTP :8080| GO_PORT
    SERVICES -->|HTTP :8083| GO_DORK
    SERVICES -->|HTTP :8085| GO_METHODOLOGY
    SERVICES -->|HTTP :8087| GO_WALKTHROUGH
    SERVICES -->|HTTP :8090| GO_WORDLIST
    SERVICES -->|HTTP :8086| GO_BOARD
    SERVICES -->|HTTP :8089| GO_CREDENTIAL

    %% Microservice to DB connections
    GO_AUTH --> GO_AUTH_DB
    GO_WORKSPACE --> GO_WORKSPACE_DB
    GO_SUBDOMAIN --> GO_SUBDOMAIN_DB
    GO_PORT --> GO_PORT_DB
    GO_DORK --> GO_DORK_DB
    GO_METHODOLOGY --> GO_METHOD_DB
    GO_WALKTHROUGH --> GO_WALK_DB
    GO_WORDLIST --> GO_WORD_DB
    GO_BOARD --> GO_BOARD_DB
    GO_CREDENTIAL --> GO_CRED_DB

    %% Shared resources
    GO_AUTH -.-> SHARED_JWT
    GO_WORKSPACE -.-> SHARED_JWT
    GO_SUBDOMAIN -.-> SHARED_JWT
    GO_PORT -.-> SHARED_JWT
    GO_DORK -.-> SHARED_JWT
    GO_METHODOLOGY -.-> SHARED_JWT
    GO_WALKTHROUGH -.-> SHARED_JWT
    GO_WORDLIST -.-> SHARED_JWT
    GO_BOARD -.-> SHARED_JWT
    GO_CREDENTIAL -.-> SHARED_JWT

    style GO_AUTH fill:#4CAF50
    style GO_WORKSPACE fill:#2196F3
    style GO_SUBDOMAIN fill:#FF9800
    style GO_PORT fill:#FF5722
    style GO_DORK fill:#9C27B0
    style GO_METHODOLOGY fill:#00BCD4
    style GO_WALKTHROUGH fill:#FFEB3B
    style GO_WORDLIST fill:#795548
    style GO_BOARD fill:#E91E63
    style GO_CREDENTIAL fill:#F44336
```

---

## 🌐 Diagrama 6: Sincronización Selectiva de Datos

```mermaid
flowchart TD
    Start([Usuario trabaja localmente]) --> CreateData{Tipo de dato creado}

    CreateData -->|Subdomain scan| SubdomainLocal[Guardar en SQLite local]
    CreateData -->|Port scan| PortLocal[Guardar en SQLite local]
    CreateData -->|Credential| CredentialLocal[🔒 Guardar encriptado localmente]
    CreateData -->|Walkthrough| WalkthroughLocal[Guardar borrador local]
    CreateData -->|Note| NoteLocal[Guardar nota privada]

    SubdomainLocal --> SubdomainDecision{Usuario decide}
    PortLocal --> PortDecision{Usuario decide}
    CredentialLocal --> CredentialDecision{Usuario decide}
    WalkthroughLocal --> WalkthroughDecision{Usuario decide}
    NoteLocal --> NoteDecision{Usuario decide}

    %% Subdomain flow
    SubdomainDecision -->|Keep private| StayLocal1[❌ Nunca sincroniza]
    SubdomainDecision -->|Share to marketplace| CheckAuth1{Conectado a Django?}
    CheckAuth1 -->|No| DjangoLogin1[Solicitar login Django]
    CheckAuth1 -->|Yes| UploadSubdomain[📤 POST /api/marketplace/]
    DjangoLogin1 --> UploadSubdomain
    UploadSubdomain --> MarkSynced1[Actualizar sync_status en SQLite]
    MarkSynced1 --> SubdomainPublic[✅ Disponible en marketplace]

    %% Port scan flow
    PortDecision -->|Keep private| StayLocal2[❌ Nunca sincroniza]
    PortDecision -->|Share results| CheckAuth2{Conectado a Django?}
    CheckAuth2 -->|No| DjangoLogin2[Solicitar login Django]
    CheckAuth2 -->|Yes| UploadPortScan[📤 POST /api/port-scans/]
    DjangoLogin2 --> UploadPortScan
    UploadPortScan --> MarkSynced2[Actualizar sync_status en SQLite]

    %% Credential flow
    CredentialDecision -->|🔒 Always private| StayLocal3[❌ NUNCA sale de la máquina]
    CredentialDecision -->|Team share| TeamOnly[📤 Compartir solo con team]
    TeamOnly --> EncryptedShare[Compartir encriptado end-to-end]

    %% Walkthrough flow
    WalkthroughDecision -->|Keep as draft| StayLocal4[❌ Solo local]
    WalkthroughDecision -->|Publish to community| CheckAuth3{Conectado a Django?}
    CheckAuth3 -->|No| DjangoLogin3[Solicitar login Django]
    CheckAuth3 -->|Yes| UploadWalkthrough[📤 POST /api/walkthroughs/]
    DjangoLogin3 --> UploadWalkthrough
    UploadWalkthrough --> MarkSynced3[Actualizar sync_status + django_id]
    MarkSynced3 --> WalkthroughPublic[✅ Publicado en synckz.com]
    WalkthroughPublic --> ReceiveInteractions[Recibir comentarios/claps]
    ReceiveInteractions --> PullUpdates[🔄 Sync service pull updates]
    PullUpdates --> UpdateLocalCache[Actualizar cache local]

    %% Note flow
    NoteDecision -->|Private| StayLocal5[❌ Solo local]
    NoteDecision -->|Backup to cloud| BackupNote[☁️ Backup opcional]
    BackupNote --> EncryptedBackup[Backup encriptado]

    %% End states
    StayLocal1 --> End1([Dato permanece 100% local])
    StayLocal2 --> End1
    StayLocal3 --> End1
    StayLocal4 --> End1
    StayLocal5 --> End1
    SubdomainPublic --> End2([Dato sincronizado y público])
    UpdateLocalCache --> End2
    EncryptedShare --> End3([Dato compartido selectivamente])
    EncryptedBackup --> End3

    style StayLocal1 fill:#4CAF50
    style StayLocal2 fill:#4CAF50
    style StayLocal3 fill:#F44336,color:#fff
    style StayLocal4 fill:#4CAF50
    style StayLocal5 fill:#4CAF50
    style SubdomainPublic fill:#2196F3
    style WalkthroughPublic fill:#2196F3
    style EncryptedShare fill:#FF9800
```

---

## 🔐 Diagrama 7: Flujo de Seguridad y Tokens

```mermaid
sequenceDiagram
    participant User as 👤 Usuario
    participant Desktop as 🖥️ Desktop App
    participant LocalAuth as 🔐 Local Auth (Go)
    participant LocalDB as 💾 SQLite
    participant Internet as ☁️ Internet
    participant Django as 🌐 Django API
    participant PostgreSQL as 🗄️ PostgreSQL

    rect rgb(230, 230, 250)
        Note over User,LocalDB: FASE 1: Autenticación Local (Siempre funciona)
        User->>Desktop: 1. Abrir app
        Desktop->>LocalAuth: 2. Check local session
        LocalAuth->>LocalDB: 3. SELECT * FROM local_users WHERE session_token = ?
        LocalDB-->>LocalAuth: 4. User found OR null

        alt User exists locally
            LocalAuth-->>Desktop: 5. Local JWT token (Go-generated)
            Desktop->>User: 6. Show dashboard (offline mode)
        else No local user
            Desktop->>User: 7. Show "Create local account"
            User->>Desktop: 8. Enter credentials
            Desktop->>LocalAuth: 9. POST /auth/register
            LocalAuth->>LocalAuth: 10. Hash password (bcrypt, cost=12)
            LocalAuth->>LocalDB: 11. INSERT user + Generate local JWT
            LocalDB-->>LocalAuth: 12. User created (id=1)
            LocalAuth-->>Desktop: 13. Local JWT token (expires 30 min)
            Note over Desktop,LocalDB: Token format: HS256, claims: {user_id, email, level, exp}
            Desktop->>User: 14. Logged in (100% offline)
        end
    end

    rect rgb(240, 255, 240)
        Note over User,PostgreSQL: FASE 2: Conexión Opcional con Django
        User->>Desktop: 15. Click "Connect to Synckz Community"
        Desktop->>User: 16. Show Django login modal
        User->>Desktop: 17. Enter Django email/password

        Desktop->>Internet: 18. Check internet connection
        Internet-->>Desktop: 19. Connection OK

        Desktop->>Django: 20. POST https://synckz.com/api/auth/login/<br/>{email, password}
        Django->>Django: 21. Authenticate CustomUser
        Django->>PostgreSQL: 22. SELECT * FROM registration_customuser WHERE email=?
        PostgreSQL-->>Django: 23. User found (id=5, level=10, etc.)

        Django->>Django: 24. Verify password (bcrypt)
        Django->>Django: 25. Generate JWT tokens<br/>- Access token (1h)<br/>- Refresh token (7 days)
        Note over Django: JWT claims: {user_id, email, username, level, credits,<br/>user_type: 'admin', exp, iat}

        Django-->>Desktop: 26. {<br/>  success: true,<br/>  access_token: "eyJhbGc...",<br/>  refresh_token: "eyJhbGc...",<br/>  user: {id, email, level, credits}<br/>}

        Desktop->>LocalDB: 27. UPDATE local_users SET<br/>django_user_id = 5,<br/>django_access_token = "eyJhbGc...",<br/>django_refresh_token = "eyJhbGc..."<br/>WHERE id = 1
        LocalDB-->>Desktop: 28. Mapping stored

        Desktop->>Desktop: 29. Store tokens in memory (secure)
        Desktop->>User: 30. "Connected as owner@synckz.com ✅"
    end

    rect rgb(255, 245, 235)
        Note over User,PostgreSQL: FASE 3: Operaciones Sincronizadas
        User->>Desktop: 31. Create walkthrough (local)
        Desktop->>LocalDB: 32. INSERT INTO local_walkthroughs<br/>(user_id=1, title, content, sync_status='local_only')
        LocalDB-->>Desktop: 33. Walkthrough created (local_id=42)

        User->>Desktop: 34. Click "Publish to Community"
        Desktop->>Desktop: 35. Check Django token expiration

        alt Token expired
            Desktop->>Django: 36. POST /api/auth/refresh/<br/>{refresh_token}
            Django->>Django: 37. Validate refresh token
            Django-->>Desktop: 38. New access_token
            Desktop->>LocalDB: 39. UPDATE django_access_token
        end

        Desktop->>Django: 40. POST /api/walkthroughs/<br/>Authorization: Bearer eyJhbGc...<br/>{title, content, tags}
        Django->>Django: 41. Verify JWT signature + expiration
        Django->>Django: 42. Extract user_id from token claims
        Django->>PostgreSQL: 43. INSERT INTO walkthrough_walkthrough<br/>(author_id=5, title, content)
        PostgreSQL-->>Django: 44. Created (django_id=123)

        Django-->>Desktop: 45. {<br/>  id: 123,<br/>  published_at: "2025-10-06T...",<br/>  url: "https://synckz.com/walkthroughs/123/"<br/>}

        Desktop->>LocalDB: 46. UPDATE local_walkthroughs SET<br/>sync_status='published',<br/>django_walkthrough_id=123<br/>WHERE local_id=42
        LocalDB-->>Desktop: 47. Updated

        Desktop->>User: 48. "Published! 🎉<br/>View: https://synckz.com/walkthroughs/123/"
    end

    rect rgb(255, 240, 245)
        Note over User,PostgreSQL: FASE 4: Sincronización de Comentarios (Pull)
        Desktop->>Desktop: 49. Sync timer triggers (every 5 min)
        Desktop->>Django: 50. GET /api/walkthroughs/123/comments/<br/>Authorization: Bearer eyJhbGc...
        Django->>PostgreSQL: 51. SELECT * FROM comments WHERE walkthrough_id=123
        PostgreSQL-->>Django: 52. Comments list
        Django-->>Desktop: 53. [{id, user, content, claps}, ...]

        Desktop->>LocalDB: 54. INSERT INTO local_walkthrough_comments<br/>(walkthrough_id=42, django_comment_id, content)
        LocalDB-->>Desktop: 55. Cached locally
        Desktop->>User: 56. Show notification: "3 new comments"
    end

    rect rgb(240, 240, 240)
        Note over User,LocalDB: FASE 5: Trabajo Offline (Token expirado o sin internet)
        User->>Desktop: 57. Continue working
        Desktop->>Internet: 58. Try sync (background)
        Internet-->>Desktop: 59. No connection ❌

        Desktop->>LocalDB: 60. All operations go to local DB
        LocalDB-->>Desktop: 61. Data saved with sync_status='pending'
        Desktop->>User: 62. "Working offline - changes will sync later"

        Note over Desktop,LocalDB: Queue stores: {operation, resource_type, data, retry_count}

        Desktop->>Internet: 63. Connection restored ✅
        Desktop->>Desktop: 64. Process sync queue
        Desktop->>Django: 65. Batch sync pending operations
        Django-->>Desktop: 66. Sync completed
        Desktop->>LocalDB: 67. Update sync_status='synced'
        Desktop->>User: 68. "Synced 5 changes ✅"
    end
```

---

## 📱 Diagrama 8: Componentes de UI y sus Estados

```mermaid
stateDiagram-v2
    [*] --> AppLaunch

    state "App Launch" as AppLaunch {
        [*] --> CheckLocalSession
        CheckLocalSession --> NoLocalUser: No local session
        CheckLocalSession --> HasLocalUser: Session found

        NoLocalUser --> ShowWelcome: First time
        ShowWelcome --> CreateLocalAccount
        CreateLocalAccount --> LocalUserCreated

        HasLocalUser --> LocalUserCreated: Resume session
    }

    state "Logged In (Local Only)" as LocalOnly {
        LocalUserCreated --> Dashboard

        state "Dashboard" as Dashboard {
            [*] --> ShowStats: Display local stats
            ShowStats --> WorkspaceList: Show workspaces
            WorkspaceList --> QuickActions: Show actions

            QuickActions --> NewScan: Start subdomain scan
            QuickActions --> NewWalkthrough: Create walkthrough
            QuickActions --> OpenSettings: Open settings
        }

        Dashboard --> SyncPanel: Show "Connect to Community" banner
    }

    state "Sync Panel" as SyncPanel {
        [*] --> NotConnected: Initial state
        NotConnected --> DjangoLoginModal: User clicks connect

        state "Django Login" as DjangoLoginModal {
            [*] --> EnterCredentials
            EnterCredentials --> Authenticating: Submit
            Authenticating --> LoginSuccess: Credentials valid
            Authenticating --> LoginError: Credentials invalid
            LoginError --> EnterCredentials: Retry
        }

        LoginSuccess --> Connected: Store tokens

        state "Connected State" as Connected {
            [*] --> ShowUserInfo: Display Django user
            ShowUserInfo --> SyncOptions: Show sync actions

            SyncOptions --> PublishWalkthrough: Publish content
            SyncOptions --> DownloadCommunity: Browse community
            SyncOptions --> BackupSettings: Backup preferences
            SyncOptions --> ShareToMarketplace: Share data

            PublishWalkthrough --> Publishing
            Publishing --> PublishSuccess: Upload complete
            Publishing --> PublishError: Network/Auth error
            PublishSuccess --> ShowUserInfo: Update UI
            PublishError --> SyncOptions: Show retry option
        }

        Connected --> Disconnect: User logs out Django
        Disconnect --> NotConnected: Clear tokens
    }

    state "Workspace View" as WorkspaceView {
        Dashboard --> OpenWorkspace: User selects workspace

        state "Workspace Detail" as WorkspaceDetail {
            [*] --> LoadWorkspaceData
            LoadWorkspaceData --> ShowSubdomains: Display subdomains
            LoadWorkspaceData --> ShowURLs: Display URLs
            LoadWorkspaceData --> ShowCredentials: Display credentials
            LoadWorkspaceData --> ShowNotes: Display notes

            ShowSubdomains --> SubdomainScanner: Start new scan
            SubdomainScanner --> ScanRunning: Scanner active
            ScanRunning --> ScanResults: Results found
            ScanResults --> SaveToLocal: Save to SQLite
            SaveToLocal --> ShowSubdomains: Update view

            ShowSubdomains --> ShareSubdomain: User wants to share
            ShareSubdomain --> CheckDjangoAuth: Need authentication?
            CheckDjangoAuth --> SyncPanel: Not connected
            CheckDjangoAuth --> UploadToMarketplace: Connected
            UploadToMarketplace --> ShareSuccess: Listed on marketplace
            ShareSuccess --> ShowSubdomains: Mark as shared
        }
    }

    state "Walkthrough Editor" as WalkthroughEditor {
        NewWalkthrough --> EditorOpen

        state "Editor Interface" as EditorOpen {
            [*] --> MarkdownEditor: Rich text editor
            MarkdownEditor --> LivePreview: Real-time preview
            LivePreview --> MarkdownEditor: Continue editing

            MarkdownEditor --> AutoSave: Every 30 seconds
            AutoSave --> SaveToSQLite: Store locally
            SaveToSQLite --> MarkdownEditor: Continue

            MarkdownEditor --> PublishButton: User ready to publish
            PublishButton --> CheckContent: Validate fields
            CheckContent --> ContentInvalid: Missing title/tags
            ContentInvalid --> MarkdownEditor: Show errors

            CheckContent --> ContentValid: All OK
            ContentValid --> PublishFlow
        }

        state "Publish Flow" as PublishFlow {
            [*] --> CheckConnection
            CheckConnection --> NoInternet: Offline
            NoInternet --> QueueForLater: Add to sync queue
            QueueForLater --> MarkdownEditor: Will publish when online

            CheckConnection --> InternetOK: Online
            InternetOK --> CheckDjangoToken: Token valid?
            CheckDjangoToken --> NoToken: Not connected
            NoToken --> SyncPanel: Prompt login

            CheckDjangoToken --> TokenValid: Connected
            TokenValid --> UploadToDjango: POST to API
            UploadToDjango --> PublishSuccess: 201 Created
            UploadToDjango --> PublishFailed: Error

            PublishFailed --> ShowError: Display error message
            ShowError --> RetryOptions: Offer retry
            RetryOptions --> UploadToDjango: Retry
            RetryOptions --> MarkdownEditor: Cancel

            PublishSuccess --> UpdateLocalRecord: Store django_id
            UpdateLocalRecord --> ShowSuccessMessage: "Published! 🎉"
            ShowSuccessMessage --> ViewOnWeb: Open in browser
            ShowSuccessMessage --> MarkdownEditor: Continue editing
        }
    }

    state "Settings Panel" as Settings {
        OpenSettings --> SettingsView

        state "Settings View" as SettingsView {
            [*] --> GeneralSettings
            GeneralSettings --> SyncSettings: Sync preferences
            GeneralSettings --> SecuritySettings: Security options
            GeneralSettings --> AppearanceSettings: Theme/UI

            SyncSettings --> AutoSyncToggle: Enable/disable auto-sync
            SyncSettings --> SyncFrequency: Set sync interval
            SyncSettings --> DataSharing: Choose what to sync

            SecuritySettings --> EncryptionKey: Manage encryption
            SecuritySettings --> ClearCache: Clear local cache
            SecuritySettings --> ExportData: Export local data

            DataSharing --> PrivacyControls
        }

        state "Privacy Controls" as PrivacyControls {
            [*] --> DefaultPrivate: Default: all local
            DefaultPrivate --> SelectiveSharing: User chooses

            SelectiveSharing --> ShareWalkthroughs: Walkthroughs only
            SelectiveSharing --> ShareNothing: Keep all local
            SelectiveSharing --> ShareAll: Sync everything
            SelectiveSharing --> CustomRules: Custom rules
        }
    }

    LocalOnly --> WorkspaceView
    WorkspaceView --> LocalOnly
    WalkthroughEditor --> LocalOnly
    Settings --> LocalOnly
```

---

## ⚙️ Diagrama 9: Configuración de Entorno

```mermaid
graph TB
    subgraph "DESARROLLO LOCAL"
        subgraph "Frontend Development"
            VITE[Vite Dev Server :5177]
            REACT[React Hot Reload]
            TYPESCRIPT[TypeScript Compiler]
        end

        subgraph "Go Services (Local)"
            GO_SERVICES[10 Go Microservices<br/>Ports: 8080-8090]
            GO_ENV[.env.local<br/>JWT_SECRET=shared_jwt_secret_for_testing_123]
        end

        subgraph "Local Databases"
            SQLITE_FILES[SQLite Files<br/>~/.synckz/data/*.db]
            SQLITE_AUTH[auth.db]
            SQLITE_WORKSPACE[workspaces.db]
            SQLITE_SUBDOMAINS[subdomains.db]
            SQLITE_WALKTHROUGHS[walkthroughs.db]
        end

        VITE --> GO_SERVICES
        GO_SERVICES --> GO_ENV
        GO_SERVICES --> SQLITE_FILES
        SQLITE_FILES --> SQLITE_AUTH
        SQLITE_FILES --> SQLITE_WORKSPACE
        SQLITE_FILES --> SQLITE_SUBDOMAINS
        SQLITE_FILES --> SQLITE_WALKTHROUGHS
    end

    subgraph "PRODUCCIÓN - DJANGO (synckz.com)"
        subgraph "Django Configuration"
            DJANGO_PROD[Django Production]
            DJANGO_ENV[Environment Variables<br/>DEBUG=False<br/>ALLOWED_HOSTS=synckz.com]
            DJANGO_CORS[CORS Configuration<br/>CORS_ALLOWED_ORIGINS]
        end

        subgraph "Database"
            POSTGRES[PostgreSQL :5432<br/>Database: huntersdb]
        end

        subgraph "Web Server"
            NGINX[Nginx Reverse Proxy]
            GUNICORN[Gunicorn WSGI]
            SSL[SSL Certificate<br/>Let's Encrypt]
        end

        NGINX --> SSL
        NGINX --> GUNICORN
        GUNICORN --> DJANGO_PROD
        DJANGO_PROD --> DJANGO_ENV
        DJANGO_PROD --> DJANGO_CORS
        DJANGO_PROD --> POSTGRES
    end

    subgraph "APLICACIÓN COMPILADA (Distribución)"
        subgraph "Desktop Executable"
            EXE[synckz.exe / synckz.app<br/>Electron/Tauri Package]
            EMBEDDED_GO[Embedded Go Services<br/>(Binarios compilados)]
            EMBEDDED_FRONTEND[Embedded Frontend<br/>(Build optimizado)]
            EMBEDDED_SQLITE[Embedded SQLite<br/>(Base de datos portátil)]
        end

        EXE --> EMBEDDED_GO
        EXE --> EMBEDDED_FRONTEND
        EXE --> EMBEDDED_SQLITE
    end

    subgraph "CONFIGURACIÓN DEL USUARIO"
        subgraph "User Data Directory"
            USER_DIR[Windows: %APPDATA%/Synckz<br/>macOS: ~/Library/Application Support/Synckz<br/>Linux: ~/.config/synckz]
            USER_SETTINGS[settings.json<br/>Preferencias del usuario]
            USER_DATABASES[*.db SQLite files<br/>Datos locales del usuario]
            USER_LOGS[logs/<br/>Archivos de log]
            USER_CACHE[cache/<br/>Caché temporal]
        end

        USER_DIR --> USER_SETTINGS
        USER_DIR --> USER_DATABASES
        USER_DIR --> USER_LOGS
        USER_DIR --> USER_CACHE
    end

    %% Conexiones entre entornos
    VITE -.->|Desarrollo| DJANGO_PROD
    EXE -.->|Producción| DJANGO_PROD
    EXE --> USER_DIR

    %% Variables de entorno compartidas
    ENV_SHARED{Variables de Entorno Compartidas}
    ENV_SHARED --> GO_ENV
    ENV_SHARED --> DJANGO_ENV

    ENV_SHARED -.->|JWT_SECRET| GO_SERVICES
    ENV_SHARED -.->|DJANGO_API_URL| VITE
    ENV_SHARED -.->|CORS_ALLOWED_ORIGINS| DJANGO_CORS

    style VITE fill:#41B883
    style DJANGO_PROD fill:#092E20
    style EXE fill:#2196F3
    style POSTGRES fill:#336791
    style NGINX fill:#009639
```

---

## 🔄 Diagrama 10: Resolución de Conflictos

```mermaid
flowchart TD
    Start([Usuario edita walkthrough publicado]) --> CheckLocalChanges{Hay cambios locales?}

    CheckLocalChanges -->|No| NoConflict1[No hay conflicto]
    CheckLocalChanges -->|Yes| FetchRemote[Fetch datos de Django]

    FetchRemote --> CompareTimestamps{Comparar timestamps}

    CompareTimestamps -->|Local más reciente| LocalNewer[Local updated_at > Django updated_at]
    CompareTimestamps -->|Django más reciente| RemoteNewer[Django updated_at > Local updated_at]
    CompareTimestamps -->|Mismo timestamp| NoConflict2[No hay conflicto]

    LocalNewer --> PushToRemote[Push cambios locales a Django]
    PushToRemote --> UpdateSuccess{Push exitoso?}
    UpdateSuccess -->|Yes| UpdateLocalTimestamp[Actualizar timestamp local]
    UpdateSuccess -->|No| PushError[Error de red/auth]
    PushError --> QueueForRetry[Agregar a cola de retry]

    RemoteNewer --> CheckLocalModified{Usuario modificó local?}
    CheckLocalModified -->|No| PullFromRemote[Pull cambios de Django]
    CheckLocalModified -->|Yes| ConflictDetected[⚠️ CONFLICTO DETECTADO]

    ConflictDetected --> ShowConflictUI[Mostrar UI de resolución]

    ShowConflictUI --> UserChoice{Usuario elige}
    UserChoice -->|Keep local| KeepLocal[Mantener versión local]
    UserChoice -->|Use remote| UseRemote[Usar versión de Django]
    UserChoice -->|Merge manually| ManualMerge[Abrir editor de merge]

    KeepLocal --> ConfirmOverwrite{Confirmar sobrescribir Django?}
    ConfirmOverwrite -->|Yes| ForcePush[Force push a Django]
    ConfirmOverwrite -->|No| ShowConflictUI
    ForceP ush --> LogConflictResolution[Log: local_version_chosen]

    UseRemote --> ConfirmDiscard{Confirmar descartar cambios locales?}
    ConfirmDiscard -->|Yes| DiscardLocal[Sobrescribir local con Django]
    ConfirmDiscard -->|No| ShowConflictUI
    DiscardLocal --> LogConflictResolution2[Log: remote_version_chosen]

    ManualMerge --> ShowMergeEditor[Mostrar editor lado a lado]
    ShowMergeEditor --> UserMerges[Usuario combina manualmente]
    UserMerges --> SaveMerged[Guardar versión fusionada]
    SaveMerged --> PushMerged[Push versión fusionada]
    PushMerged --> LogConflictResolution3[Log: manual_merge]

    PullFromRemote --> UpdateLocalData[Actualizar SQLite local]
    UpdateLocalData --> NotifyUser1[Notificar: "Walkthrough actualizado desde comunidad"]

    UpdateLocalTimestamp --> NotifyUser2[Notificar: "Cambios publicados"]

    NoConflict1 --> End1([Sin acción requerida])
    NoConflict2 --> End1
    QueueForRetry --> End2([Reintentará más tarde])
    LogConflictResolution --> End3([Conflicto resuelto])
    LogConflictResolution2 --> End3
    LogConflictResolution3 --> End3
    NotifyUser1 --> End3
    NotifyUser2 --> End3

    style ConflictDetected fill:#FF5722,color:#fff
    style ShowConflictUI fill:#FF9800
    style ManualMerge fill:#FFC107
    style KeepLocal fill:#4CAF50
    style UseRemote fill:#2196F3
```

---

## 📊 RESUMEN DE COMPONENTES

### **Desktop App (Local)**
- **Frontend**: React + TypeScript (puerto 5177)
- **Backend**: 10 microservicios Go (puertos 8080-8090)
- **Base de datos**: SQLite (archivos locales)
- **Funciona**: 100% offline, sincronización opcional

### **Django Backend (synckz.com)**
- **API**: Django REST Framework + JWT
- **Base de datos**: PostgreSQL
- **Servicios**: Auth, Social, Marketplace, Teams
- **Propósito**: Comunidad, compartir datos, backup

### **Sincronización**
- **Modo**: Híbrido (local-first con sync opcional)
- **Datos privados**: NUNCA salen de la máquina
- **Datos públicos**: Usuario decide qué compartir
- **Conflictos**: Resolución manual con UI intuitiva

---

¿Te gustaría que profundice en algún diagrama específico o genere diagramas adicionales para otros aspectos del sistema?
