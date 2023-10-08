use crate::config::{self, Config};
use std::sync::Arc;

use askama::Template;
use axum::{
    async_trait,
    error_handling::HandleErrorLayer,
    extract::{FromRequestParts, State},
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{self, get},
    BoxError, Form, RequestExt, Router,
};

use password_hash::PasswordVerifier;
use scrypt::Scrypt;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tower_sessions::{session::SessionError, Session, SessionManagerLayer};

pub struct Server {
    router: Router<()>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    err: Option<String>,
}

#[derive(Template)]
#[template(path = "tools.html")]
struct ToolsTemplate;

#[derive(Template)]
#[template(path = "not-found.html")]
struct NotFoundTemplate;

#[derive(Template)]
#[template(path = "crash.html")]
struct CrashTemplate {
    err_str: String,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuthedUser {
    username: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        use axum::RequestPartsExt;

        let sess = parts.extract::<Session>().await.expect("got the session");
        // let Extension(state) = parts.extract::<Extension<Arc<ServerState>>>().await.expect("got the state");
        // let state = parts.extract::<State<Arc<ServerState>>>().await.expect("got the server state");

        let user = sess
            .get("user")
            .unwrap_or(None)
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(user)
    }
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Server error")]
    ServerError(#[from] anyhow::Error),
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Session problem: {0}")]
    Sess(#[from] SessionError),
}

type AppResult<T> = Result<T, AppError>;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::ServerError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(
                    CrashTemplate {
                        err_str: format!("{}", err),
                    }
                    .render()
                    .expect("render error template"),
                ),
            )
                .into_response(),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Html(
                    IndexTemplate {
                        err: Some("Unauthorized".to_string()),
                    }
                    .render()
                    .expect("render unauthorized"),
                ),
            )
                .into_response(),
            AppError::Sess(err) => AppError::ServerError(anyhow::anyhow!(err)).into_response(),
        }
    }
}

async fn root_get(user: Option<AuthedUser>) -> Response {
    match user {
        Some(_) => Redirect::to("/tools").into_response(),
        None => Html(IndexTemplate { err: None }.render().unwrap()).into_response(),
    }
}

async fn root_post(
    sess: Session,
    State(state): State<Arc<ServerState>>,
    Form(login): Form<LoginForm>,
) -> AppResult<Response> {
    match auth(state, &login) {
        Ok(_) => {
            sess.insert(
                "user",
                AuthedUser {
                    username: login.username,
                },
            )?;
            Ok(axum::response::Redirect::to("/tools").into_response())
        }
        Err(_) => Err(AppError::Unauthorized),
    }
}

fn auth(state: Arc<ServerState>, login: &LoginForm) -> anyhow::Result<()> {
    let phc = state
        .config
        .users
        .get(&login.username)
        .ok_or(anyhow::anyhow!("No user found"))?;
    Scrypt.verify_password(login.password.as_bytes(), &phc.password_hash())?;
    Ok(())
}

async fn auth_middleware<B>(mut request: Request<B>, next: Next<B>) -> Response
where
    B: Send + 'static,
{
    match request.extract_parts::<AuthedUser>().await {
        Ok(_) => next.run(request).await,
        Err(status_code) => (
            status_code,
            Html(IndexTemplate { err: None }.render().unwrap()),
        )
            .into_response(),
    }
}

struct ServerState {
    config: Config,
}

impl Server {
    pub async fn new() -> anyhow::Result<Self> {
        let config = config::read_config().await?;

        let state = Arc::new(ServerState { config });

        let trace_layer = ServiceBuilder::new().layer(TraceLayer::new_for_http());
        let session_store = tower_sessions::MemoryStore::default();
        let session_service = ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: BoxError| async {
                StatusCode::BAD_REQUEST
            }))
            .layer(SessionManagerLayer::new(session_store));

        let app = Router::new()
            .route("/", get(root_get).post(root_post))
            .nest(
                "/tools",
                Router::new()
                    .route(
                        "/",
                        get(|| async { Html(ToolsTemplate {}.render().unwrap()) }),
                    )
                    .layer(axum::middleware::from_fn(
                        // Arc::clone(&state),
                        auth_middleware,
                    )), // .layer(axum::middleware::from_extractor::<AuthedUser>()),
            )
            .fallback(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Html(NotFoundTemplate {}.render().unwrap()),
                )
            })
            .layer(session_service)
            .layer(trace_layer)
            .with_state(state)
            .nest_service("/static", routing::get_service(ServeDir::new("static")));

        Ok(Server { router: app })
    }

    pub async fn run(self, addr: std::net::SocketAddr) -> anyhow::Result<()> {
        tracing::info!("Listening on address {:?}", addr);
        axum::Server::bind(&addr)
            .serve(self.router.into_make_service())
            .await?;
        Ok(())
    }
}
