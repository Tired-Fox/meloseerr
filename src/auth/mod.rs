use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, serde::ts_milliseconds};

use std::{borrow::Cow, collections::HashMap, convert::Infallible, sync::{Arc, Mutex}};
use jsonwebtoken::DecodingKey;
use crate::error::Error;

#[derive(Default, Clone)]
pub struct KeyStore {
    pub(crate) keys: Arc<Mutex<HashMap<Cow<'static, str>, DecodingKey>>>
}
impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish_non_exhaustive()
    }
}

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

#[derive(sqlx::prelude::FromRow, Serialize, Deserialize, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: u32,
    pub user_agent: String,
    #[serde(with = "ts_milliseconds")]
    pub last_active: DateTime<Utc>,
}
impl Session {
    pub async fn create(pool: &sqlx::SqlitePool, user_id: u32, user_agent: &str) -> Result<Session, Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query_as("INSERT INTO session (id, user_id, user_agent, last_active) VALUES (?, ?, ?, ?) RETURNING *")
            .bind(uuid::Uuid::now_v7().to_string())
            .bind(user_id)
            .bind(user_agent)
            .bind(Utc::now().timestamp_millis())
            .fetch_one(&mut *conn)
            .await
            .map_err(Into::into)
    }

    pub async fn get_by_user_agent(pool: &sqlx::SqlitePool, user_agent: &str) -> Result<Session, Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query_as("SELECT * FROM session WHERE user_agent = ?")
            .bind(user_agent)
            .fetch_one(&mut *conn)
            .await
            .map_err(Into::into)
    }

    pub async fn get_by_id(pool: &sqlx::SqlitePool, id: &str) -> Result<Option<Session>, Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query_as("SELECT * FROM session WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(Into::into)
    }

    pub async fn get_refresh_token(&self, pool: &sqlx::SqlitePool) -> Result<Option<RefreshToken>, Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query_as("SELECT * FROM refresh_token WHERE session_id = ?")
            .bind(&self.id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(Into::into)
    }

    pub async fn remove_all_refresh_tokens(&self, pool: &sqlx::SqlitePool) -> Result<Option<RefreshToken>, Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query_as("DELETE FROM refresh_token WHERE session_id = ?")
            .bind(&self.id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(Into::into)
    }
}

#[derive(sqlx::prelude::FromRow, Serialize, Deserialize, Clone)]
pub struct RefreshToken {
    pub id: String,
    pub session_id: String,
    #[serde(with = "ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_milliseconds")]
    pub expires_at: DateTime<Utc>,
}

impl RefreshToken {
    pub async fn get_by_id(pool: &sqlx::SqlitePool, id: &str) -> Result<Option<Self>, Error> {
        let mut conn = pool.acquire().await?;

        let token: Option<Self> = sqlx::query_as("SELECT * FROM refresh_token WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    
        Ok(token)
    }

    pub async fn create(pool: &sqlx::SqlitePool, session: &str) -> Result<String, Error> {
        let mut conn = pool.acquire().await?;

        let new_token = uuid::Uuid::now_v7().to_string();
        let now = Utc::now();

        sqlx::query("INSERT INTO refresh_token (id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
            .bind(&new_token)
            .bind(session)
            .bind(now.timestamp_millis())
            .bind((now + chrono::Duration::days(14)).timestamp_millis())
            .execute(&mut *conn)
            .await?;
    
        Ok(new_token)
    }

    pub async fn rotate(&self, pool: &sqlx::SqlitePool, session: &str) -> Result<String, Error> {
        let mut conn = pool.acquire().await?;

        let new_token = uuid::Uuid::now_v7().to_string();
        let now = Utc::now();

        sqlx::query("
            DELETE FROM refresh_token WHERE id = ?;
            INSERT INTO refresh_token (id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?);
        ")
            .bind(&self.id)
            .bind(&new_token)
            .bind(session)
            .bind(now.timestamp_millis())
            .bind((now + chrono::Duration::days(14)).timestamp_millis())
            .execute(&mut *conn)
            .await?;
    
        Ok(new_token)
    }

    pub async fn rotate_by_id(pool: &sqlx::SqlitePool, session: &str, id: &str) -> Result<String, Error> {
        let mut conn = pool.acquire().await?;

        let new_token = uuid::Uuid::now_v7().to_string();
        let now = Utc::now();

        sqlx::query("
            DELETE FROM refresh_token WHERE id = ?;
            INSERT INTO refresh_token (id, session_id, created_at, expires_at) VALUES (?, ?, ?, ?);
        ")
            .bind(id)
            .bind(&new_token)
            .bind(session)
            .bind(now.timestamp_millis())
            .bind((now + chrono::Duration::days(14)).timestamp_millis())
            .execute(&mut *conn)
            .await?;
    
        Ok(new_token)
    }

    pub async fn revoke(&self, pool: &sqlx::SqlitePool) -> Result<(), Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query("DELETE FROM refresh_token WHERE id = ?")
            .bind(&self.id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    pub async fn revoke_by_id(pool: &sqlx::SqlitePool, id: &str) -> Result<(), Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query("DELETE FROM refresh_token WEHRE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}

#[derive(sqlx::prelude::FromRow, Serialize, Deserialize, Clone)]
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
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("username", &self.username)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl User {
    pub async fn count(pool: &sqlx::SqlitePool) -> Result<usize, Error> {
        let mut conn = pool.acquire().await?;

        let v: Option<u32> = sqlx::query_scalar("SELECT COUNT(id) FROM user")
            .fetch_optional(&mut *conn)
            .await?;

        Ok(v.unwrap_or_default() as usize)
    }

    pub async fn username_exists(pool: &sqlx::SqlitePool, username: &str) -> Result<bool, Error> {
        let mut conn = pool.acquire().await?;

        let v: Option<u32> = sqlx::query_scalar("SELECT COUNT(id) FROM user WHERE username=?")
            .bind(username)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(v.is_some())
    }

    pub async fn create(pool: &sqlx::SqlitePool, admin: bool, username: &str, password: &str) -> Result<(), Error> {
        let mut conn = pool.acquire().await?;

        let argon2 = argon2::Argon2::default();
        
        let mut hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), "meloseerr".as_bytes(), &mut hash).unwrap();

        sqlx::query("INSERT INTO user (admin, username, permissions, display_name, password, version) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(admin)
            .bind(username)
            .bind(0u32)
            .bind(None::<String>)
            .bind(String::from_utf8_lossy(&hash))
            .bind(uuid::Uuid::now_v7().to_string())
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    pub async fn get_by_id(pool: &sqlx::SqlitePool, id: u32) -> Result<Option<Self>, Error> {
        let mut conn = pool.acquire().await?;

        let v: Option<Self> = sqlx::query_as("SELECT * FROM user WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(v)
    }

    pub async fn login(pool: &sqlx::SqlitePool, keys: &KeyStore, username: &str, password: &str, user_agent: &str) -> Result<(String, String), Error> {
        let mut conn = pool.acquire().await?;

        let user: User = sqlx::query_as("SELECT * FROM user WHERE username = ?")
            .bind(username)
            .fetch_one(&mut *conn)
            .await?;

        let argon2 = argon2::Argon2::default();
        
        let mut hash = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), "meloseerr".as_bytes(), &mut hash).unwrap();
        let hash = String::from_utf8_lossy(&hash);

        if user.password != hash {
            return Err("invalid password".into())
        }

        let session = match Session::get_by_user_agent(pool, user_agent).await {
            Ok(s) => s,
            Err(_) => Session::create(pool, user.id, user_agent).await?
        };

        session.remove_all_refresh_tokens(pool).await?;

        let (auth, decode_key) = generate_auth_token(user.id, &user.version, &session.id)?;
        let refresh = RefreshToken::create(pool, &session.id).await?;

        keys.insert(session.id, decode_key);

        Ok((auth, refresh))
    }

    /// Authenticates the jwt with the current users and return the user with their active session 
    pub async fn authenticate(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<(User, String), Error> {
        let mut conn = pool.acquire().await?;

        let header = jsonwebtoken::decode_header(jwt)?;
        let kid = header.kid.as_deref().ok_or(Error::wrap(AuthorizationError::Unauthorized))?;

        let decoding_key = keys.get(&kid).ok_or(Error::wrap(AuthorizationError::Unauthorized))?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_issuer(&["meloseerr"]);
        validation.set_audience(&["meloseerr"]);
        let token = jsonwebtoken::decode::<Claims>(
            jwt,
            &decoding_key,
            &validation
        )?;

        let user: User = sqlx::query_as("SELECT * FROM user WHERE id = ?")
            .bind(token.claims.sub)
            .fetch_one(&mut *conn)
            .await?;

        if token.claims.ver != user.version { 
            return Err(Error::wrap(AuthorizationError::RevokedSession));
        }

        Ok((user, token.claims.ssn))
    }

    pub async fn refresh(pool: &sqlx::SqlitePool, keys: &KeyStore, token: &str) -> Result<(String, String), Error> {
        let token = RefreshToken::get_by_id(pool, token).await?.ok_or(Error::unauthorized())?;
        let session = Session::get_by_id(pool, &token.session_id).await?.ok_or(Error::unauthorized())?;
        let user = User::get_by_id(pool, session.user_id).await?.ok_or(Error::unauthorized())?;

        let refresh = RefreshToken::rotate_by_id(pool, &session.id, &token.id).await?;
        let (auth, decode_key) = generate_auth_token(user.id, &user.version, &session.id)?;

        keys.insert(session.id.clone(), decode_key);

        Ok((auth, refresh))
    }

    pub async fn logout(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<(), Error> {
        let (_, session): (User, String) = Self::authenticate(pool, keys, jwt).await?;

        Self::logout_session(pool, keys, &session).await?;

        Ok(())
    }

    pub async fn logout_all_sessions(pool: &sqlx::SqlitePool, keys: &KeyStore, jwt: &str) -> Result<(), Error> {
        let (user, _): (User, String) = Self::authenticate(pool, keys, jwt).await?;

        let mut conn = pool.acquire().await?;

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
            .await?;

        keys.clear();

        Ok(())
    }

    pub async fn logout_session(pool: &sqlx::SqlitePool, keys: &KeyStore, session: &str) -> Result<(), Error> {
        let mut conn = pool.acquire().await?;

        sqlx::query("DELETE FROM refresh_token WHERE session_id = ?")
            .bind(&session)
            .execute(&mut *conn)
            .await?;

        keys.remove(session);

        Ok(())
    }
}

#[derive(Debug, strum::Display)]
pub enum AuthorizationError {
    Unauthorized,
    JWTDecode,
    UserNotFound,
    RevokedSession,
}
impl std::error::Error for AuthorizationError {}

#[derive(Debug, strum::Display)]
pub enum LoginError {
    UserNotFound,
    Unauthorized,
    InvalidJwt,
}
impl std::error::Error for LoginError {}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Clone)]
pub struct AuthLayer {
    pub state: crate::State
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware { inner, state: self.state.clone() }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    state: crate::State
 }

impl<S> tower::Service<axum::extract::Request> for AuthMiddleware<S>
where
    S: tower::Service<axum::extract::Request, Response = axum::response::Response, Error = Infallible> + Send + 'static,
    S::Future: Send + 'static
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        use axum::response::Response;

        let auth_header = req.headers()
            .get("Authorization")
            .map(|v| v.to_str().unwrap().to_string())
            .and_then(|v| v.strip_prefix("Bearer ").map(ToString::to_string));
        let future = self.inner.call(req);
        let state = self.state.clone();

        Box::pin(async move {
            let authorization = match auth_header {
                Some(auth) => auth,
                None => return Ok(Response::builder()
                    .status(401)
                    .body(axum::body::Body::new("Unauthorized".to_string()))
                    .unwrap())
            };

            if User::authenticate(&state.pool, &state.key_store, &authorization).await.is_err() {
                return Ok(Response::builder()
                    .status(401)
                    .body(axum::body::Body::new("Unauthorized".to_string()))
                    .unwrap())
            }

            future.await
        })
    }
}


#[derive(Deserialize)]
#[serde(rename_all="camelCase")]
pub struct RefreshQuery {
    pub refresh_token: String
}

pub async fn refresh(
    axum::extract::State(state): axum::extract::State<crate::State>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::{body::Body, response::Response};

    let refresh_token = match headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")) {
        Some(token) => token,
        None => return Response::builder()
            .status(401)
            .body(Body::new("Unauthorized".to_string()))
            .unwrap()
    };

    match User::refresh(&state.pool, &state.key_store, refresh_token).await {
        Ok(new_tokens) => Response::builder()
            .status(200)
            .body(Body::new(serde_json::to_string(&new_tokens).unwrap()))
            .unwrap(),
        Err(_e) => Response::builder()
            .status(401)
            .body(Body::new("Unauthorized".to_string()))
            .unwrap()
    }
}

fn generate_auth_token(user: u32, version: &str, session: &str) -> jsonwebtoken::errors::Result<(String, jsonwebtoken::DecodingKey)> {
    let now = Utc::now();
    let secret = uuid::Uuid::now_v7().to_string();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(session.to_string());

    let token = jsonwebtoken::encode(
        &header,
        &Claims {
            sub: user,
            ver: version.to_string(),
            iat: now,
            exp: now + chrono::Duration::minutes(30),
            iss: "meloseerr".to_string(),
            aud: "meloseerr".to_string(),
            ssn: session.to_string(),
        },
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())
    )?;
    Ok((token, jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())))
}