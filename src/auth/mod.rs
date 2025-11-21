use std::{borrow::Cow, collections::HashMap, sync::{Arc, Mutex}};

#[cfg(feature="ssr")]
use jsonwebtoken::DecodingKey;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, serde::ts_milliseconds};

#[cfg(feature="ssr")]
#[derive(Default, Clone)]
pub struct KeyStore {
    pub(crate) keys: Arc<Mutex<HashMap<Cow<'static, str>, DecodingKey>>>
}
#[cfg(feature="ssr")]
impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish_non_exhaustive()
    }
}

#[cfg(feature="ssr")]
impl KeyStore {
    pub fn get(&self, id: &str) -> Option<DecodingKey> {
        self.keys.lock().unwrap().get(id).cloned()
    }

    pub fn insert(&self, kid: impl Into<Cow<'static, str>>, key: DecodingKey) -> Option<DecodingKey> {
        self.keys.lock().unwrap().insert(kid.into(), key)
    }

    pub fn remove(&self, kid: &str) -> Option<DecodingKey> {
        self.keys.lock().unwrap().remove(kid)
    }

    pub fn clear(&self) {
        *self.keys.lock().unwrap() = HashMap::default();
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature="ssr", derive(sqlx::prelude::FromRow))]
pub struct Session {
    pub id: String,
    pub user_id: u32,
    pub user_agent: String,
    #[serde(with = "ts_milliseconds")]
    pub last_active: DateTime<Utc>,
}
#[cfg(feature="ssr")]
impl Session {
    pub async fn create(pool: &sqlx::SqlitePool, user_id: u32, user_agent: &str) -> Result<Session, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query_as("INSERT INTO session (id, user_id, user_agent, last_active) VALUES (?, ?, ?, ?) RETURNING *")
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(user_id)
            .bind(user_agent)
            .bind(Utc::now().timestamp_millis())
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_by_user_agent(pool: &sqlx::SqlitePool, user_agent: &str) -> Result<Session, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query_as("SELECT * FROM session WEHRE user_agent = ?")
            .bind(user_agent)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_by_id(pool: &sqlx::SqlitePool, id: &str) -> Result<Session, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query_as("SELECT * FROM session WEHRE id = ?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_refresh_token(&self, pool: &sqlx::SqlitePool) -> Result<Option<RefreshToken>, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query_as("SELECT * FROM refresh_token WHERE session_id = ?")
            .bind(&self.id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn remove_all_refresh_tokens(&self, pool: &sqlx::SqlitePool) -> Result<Option<RefreshToken>, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query_as("DELETE FROM refresh_token WHERE session_id = ?")
            .bind(&self.id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| e.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature="ssr", derive(sqlx::prelude::FromRow))]
pub struct RefreshToken {
    pub id: String,
    pub session_id: String,
    #[serde(with = "ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_milliseconds")]
    pub expires_at: DateTime<Utc>,
}

#[cfg(feature="ssr")]
impl RefreshToken {
    pub async fn create(pool: &sqlx::SqlitePool, session: &str) -> Result<String, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        let new_token = uuid::Uuid::now_v7().to_string();
        let now = Utc::now();

        sqlx::query("INSERT INTO refresh_token (id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
            .bind(&new_token)
            .bind(session)
            .bind(now.timestamp_millis())
            .bind((now + chrono::Duration::days(14)).timestamp_millis())
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
    
        Ok(new_token)
    }

    pub async fn rotate(&self, pool: &sqlx::SqlitePool, session: &str) -> Result<String, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        let new_token = uuid::Uuid::now_v7().to_string();
        let now = Utc::now();

        sqlx::query("
            DELETE FROM refresh_token WEHRE id = ?;
            INSERT INTO refresh_token (id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?);
        ")
            .bind(&self.id)
            .bind(&new_token)
            .bind(session)
            .bind(now.timestamp_millis())
            .bind((now + chrono::Duration::days(14)).timestamp_millis())
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
    
        Ok(new_token)
    }

    pub async fn rotate_by_id(pool: &sqlx::SqlitePool, session: &str, id: &str) -> Result<String, String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        let new_token = uuid::Uuid::now_v7().to_string();
        let now = Utc::now();

        sqlx::query("
            DELETE FROM refresh_token WEHRE id = ?;
            INSERT INTO refresh_token (id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?);
        ")
            .bind(id)
            .bind(&new_token)
            .bind(session)
            .bind(now.timestamp_millis())
            .bind((now + chrono::Duration::days(14)).timestamp_millis())
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;
    
        Ok(new_token)
    }

    pub async fn revoke(&self, pool: &sqlx::SqlitePool) -> Result<(), String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM refresh_token WHERE id = ?")
            .bind(&self.id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn revoke_by_id(pool: &sqlx::SqlitePool, id: &str) -> Result<(), String> {
        let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

        sqlx::query("DELETE FROM refresh_token WEHRE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature="ssr", derive(sqlx::prelude::FromRow))]
pub struct User {
    pub id: u32,

    pub admin: bool,
    pub username: String,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub password: String,
    pub permissions: u32,
    pub version: String,

    #[serde(default, skip_serializing_if="Option::is_none")]
    pub display_name: Option<String>,
}

#[cfg(feature="ssr")]
impl User {
    pub async fn count(pool: &sqlx::SqlitePool) -> sqlx::Result<usize> {
        let mut conn = pool.acquire().await?;

        let v: Option<u32> = sqlx::query_scalar("SELECT COUNT(id) FROM user")
            .fetch_optional(&mut *conn)
            .await?;

        Ok(v.unwrap_or_default() as usize)
    }

    pub async fn username_exists(pool: &sqlx::SqlitePool, username: &str) -> sqlx::Result<bool> {
        let mut conn = pool.acquire().await?;

        let v: Option<u32> = sqlx::query_scalar("SELECT COUNT(id) FROM user WHERE username=?")
            .bind(username)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(v.is_some())
    }

    pub async fn create(pool: &sqlx::SqlitePool, admin: bool, username: &str, password: &str) -> sqlx::Result<()> {
        let mut conn = pool.acquire().await?;

        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = argon2::Argon2::default();
        
        let mut hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_ref().as_bytes(), &mut hash).unwrap();

        sqlx::query("INSERT INTO user (admin, username, permissions, display_name, password, version) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(admin)
            .bind(username)
            .bind(0u32)
            .bind(None::<String>)
            .bind(String::from_utf8_lossy(&hash))
            .bind(uuid::Uuid::now_v7().to_string())
            .execute(&mut *conn)
            .await
            .map(|_| ())
    }

    pub async fn login(pool: &sqlx::SqlitePool, keys: &KeyStore, username: &str, password: &str, user_agent: &str) -> Result<(String, String), LoginError> {
        let mut conn = pool.acquire().await.map_err(|_| LoginError::Unauthorized)?;

        let user: User = sqlx::query_as("SELECT * FROM user WHERE username = ?")
            .bind(username)
            .fetch_one(&mut *conn)
            .await
            .map_err(|_| LoginError::UserNotFound)?;

        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let argon2 = argon2::Argon2::default();
        
        let mut hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), salt.as_ref().as_bytes(), &mut hash).unwrap();
        let hash = String::from_utf8_lossy(&hash);

        if user.password != hash { return Err(LoginError::Unauthorized) }

        let session = match Session::get_by_user_agent(pool, user_agent).await {
            Ok(s) => s,
            Err(_) => Session::create(pool, user.id, user_agent).await.map_err(|_| LoginError::Unauthorized)?
        };

        session.remove_all_refresh_tokens(pool).await.map_err(|_| LoginError::Unauthorized)?;

        let now = Utc::now();
        let secret = uuid::Uuid::now_v7().to_string();
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);

        let auth = jsonwebtoken::encode(
            &header,
            &Claims {
                sub: user.id,
                ver: user.version,
                iat: now,
                exp: now + chrono::Duration::minutes(30),
                iss: "meloseerr".to_string(),
                aud: "meloseerr".to_string(),
                ssn: session.id.clone(),
            },
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())
        ).map_err(|_| LoginError::InvalidJwt)?;
        let refresh = RefreshToken::create(pool, &session.id).await.map_err(|_| LoginError::InvalidJwt)?;

        keys.insert(session.id, jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()));

        Ok((auth, refresh))
    }

    /// Authenticates the jwt with the current users and return the user with their active session 
    pub async fn authenticate(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<(User, String), AuthorizationError> {
        let mut conn = pool.acquire().await.map_err(|_| AuthorizationError::Unauthorized)?;

        let header = jsonwebtoken::decode_header(jwt).map_err(|_| AuthorizationError::Unauthorized)?;
        let kid = header.kid.as_deref().ok_or(AuthorizationError::Unauthorized)?;

        let decoding_key = keys.get(&kid).ok_or(AuthorizationError::Unauthorized)?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_issuer(&["meloseerr"]);
        validation.set_audience(&["meloseerr"]);
        let token = jsonwebtoken::decode::<Claims>(
            jwt,
            &decoding_key,
            &validation
        ).map_err(|_| AuthorizationError::JWTDecode)?;

        let user: User = sqlx::query_as("SELECT * FROM user WHERE id = ?")
            .bind(token.claims.sub)
            .fetch_one(&mut *conn)
            .await
            .map_err(|_| AuthorizationError::UserNotFound)?;

        if token.claims.ver != user.version { 
            return Err(AuthorizationError::RevokedSession);
        }

        Ok((user, token.claims.ssn))
    }

    pub async fn refresh(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<String, String> {
        let (user, session): (User, String) = Self::authenticate(pool, keys, jwt).await.map_err(|e| e.to_string())?;

        Err("token refreshing is currently unsupported".to_string())
    }

    pub async fn logout(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<(), String> {
        let (_, session): (User, String) = Self::authenticate(pool, keys, jwt).await.map_err(|e| e.to_string())?;

        Self::logout_session(pool, keys, &session).await.map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn logout_all_sessions(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<(), LoginError> {
        let (user, _): (User, String) = Self::authenticate(pool, keys, jwt).await.map_err(|_| LoginError::Unauthorized)?;

        let mut conn = pool.acquire().await.map_err(|_| LoginError::Unauthorized)?;

        sqlx::query("
            DELETE FROM refresh_token
            WHERE id IN (
                SELECT rt.id
                FROM refresh_token AS rt
                JOIN session ON session.id = rt.session_id
                WHERE session.user_id = ?
            )
        ")
            .bind(user.id)
            .execute(&mut *conn)
            .await
            .map_err(|_| LoginError::Unauthorized)?;

        keys.clear();

        Ok(())
    }

    pub async fn logout_session(pool: &sqlx::SqlitePool, keys: &KeyStore, session: &str) -> Result<(), LoginError> {
        let mut conn = pool.acquire().await.map_err(|_| LoginError::Unauthorized)?;

        sqlx::query("DELETE FROM refresh_token WHERE session_id = ?")
            .bind(&session)
            .execute(&mut *conn)
            .await
            .map_err(|_| LoginError::Unauthorized)?;

        keys.remove(session);

        Ok(())
    }
}

#[derive(strum::Display)]
pub enum AuthorizationError {
    Unauthorized,
    JWTDecode,
    UserNotFound,
    RevokedSession,
}

#[derive(strum::Display)]
pub enum LoginError {
    UserNotFound,
    Unauthorized,
    InvalidJwt,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    pub sub: u32,
    pub ver: String,
    #[serde(with = "ts_milliseconds")]
    pub iat: DateTime<Utc>,
    #[serde(with = "ts_milliseconds")]
    pub exp: DateTime<Utc>,
    pub iss: String,
    pub aud: String,
    pub ssn: String,
}