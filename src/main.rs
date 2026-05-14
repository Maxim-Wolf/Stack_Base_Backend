use axum::{
    Json, Router,
    extract::State,
    http::{Response, StatusCode},
    routing::{get, post, put},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode,decode, DecodingKey, Validation, TokenData};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use bcrypt::{hash, verify};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Pool, types::Text};
use std::env;

#[derive(Serialize, Deserialize)]
pub struct AuthStruct {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
#[derive(Serialize, Deserialize)]
pub struct ResponseOk {
    pub response: String,
    pub status: i32,
}
// --- MAIN & ROUTING ---
#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    use tower_http::cors::CorsLayer;

    let cors = CorsLayer::new()
        .allow_origin(
            "https://stack-base.org"
                .parse::<axum::http::HeaderValue>()
                .unwrap(),
        )
        .allow_methods([
            axum::http::Method::POST,
            axum::http::Method::GET,
            axum::http::Method::PUT,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([axum::http::HeaderName::from_static("content-type")])
        .allow_credentials(true);

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is missing");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Database connection failed");

    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/check_session",get(check_session))
        .layer(cors)
        .with_state(pool);

    let addr = "192.168.10.2:4060";
    println!("🚀 Server läuft auf http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<AuthStruct>,
) -> Result<Json<ResponseOk>, StatusCode> {
    println!("password: {}",payload.password); println!("email: {}",payload.email.to_lowercase());
    let email = payload.email.to_lowercase().to_string();
    let password_hashed = hash(&payload.password, 10).map_err(|e| {
        println!("ERROR HASHING PASSWORD {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let _res = sqlx::query!(
        "INSERT INTO users (email, password) VALUES ($1,$2)",
        email,
        password_hashed
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        println!("ERROR CREATING USER {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ResponseOk {
        response: "succes".to_string(),
        status: 200,
    }))
}
async fn login(
    jar: CookieJar,
    State(pool): State<PgPool>,
    Json(payload): Json<AuthStruct>,
) ->Result<(CookieJar, Json<ResponseOk>), StatusCode> {
    let email = payload.email.to_lowercase();
    let pw_hashed_raw = sqlx::query!("SELECT password FROM users WHERE email = $1", email)
        .fetch_one(&pool)
        .await
        .map_err(|e| {
            println!("ERROR SELECTING PASSWORD: {}", e);
            StatusCode::BAD_REQUEST
        })?;
    let pw_hashed = pw_hashed_raw.password.ok_or(StatusCode::BAD_REQUEST)?;
    let is_ok = verify(&payload.password, &pw_hashed).map_err(|_| StatusCode::UNAUTHORIZED)?;
    if (is_ok) {
        let user_uuid_raw = sqlx::query!(
            "SELECT user_uuid as user_uuid from users WHERE email = $1",
            email
        )
        .fetch_one(&pool)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let user_uuid = user_uuid_raw.user_uuid.ok_or(StatusCode::UNAUTHORIZED)?;
        let token = create_jwt(user_uuid);
        let cookie = Cookie::build(("jwt", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::None)
        .secure(true) // wichtig bei HTTPS!
        .build();
        let jar = jar.add(cookie);
        Ok((
            jar,
            Json(ResponseOk {
                response: "success".to_string(),
                status: 200,
            }),
        ))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
fn create_jwt(user_id: String) -> String {
    let secret = env::var("SECRETKEY").expect("SECRETKEY is missing");
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(2))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .unwrap()
}
fn verify_jwt(token: &str) -> Result<Claims, StatusCode> {
    let secret = env::var("SECRETKEY").expect("SECRETKEY is missing");
    let token_data: TokenData<Claims> = decode(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(token_data.claims)
}
async fn check_session (
jar: CookieJar,
State(pool): State<PgPool>
) ->Result<Json<ResponseOk>,StatusCode>{
    let token = jar.get("jwt").map(|c|{
        c.value().to_string()
    }).ok_or(StatusCode::UNAUTHORIZED)?;
    let _claims = verify_jwt(&token)?;
    Ok(Json(ResponseOk { response: ("Autherized".to_string()), status: (200) }))
}