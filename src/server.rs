use askama::Template;
use axum::{
    async_trait,
    error_handling::HandleErrorLayer,
    extract::{FromRequest, FromRequestParts},
    http::{request::Parts, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{self, get, post},
    BoxError, Form, RequestExt, RequestPartsExt, Router,
};
use tower::ServiceExt;

use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tower_sessions::{Session, SessionManagerLayer};

pub struct Server {
    router: Router<()>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Template)]
#[template(path = "tools.html")]
struct ToolsTemplate;

#[derive(Template)]
#[template(path = "not-found.html")]
struct NotFoundTemplate;

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

        let user = sess
            .get("user")
            .unwrap_or(None)
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(user)
    }
}

async fn root_get(user: Option<AuthedUser>) -> Response {
    match user {
        Some(_) => Redirect::to("/tools").into_response(),
        None => Html(IndexTemplate {}.render().unwrap()).into_response(),
    }
}

async fn root_post(sess: Session, Form(login): Form<LoginForm>) -> Response {
    // TODO check the password!
    sess.insert(
        "user",
        AuthedUser {
            username: login.username,
        },
    )
    .unwrap();

    axum::response::Redirect::to("/").into_response()
}

async fn auth_middleware<B>(
    // _state: axum::extract::State<()>,
    mut request: Request<B>,
    next: Next<B>,
) -> Response
where
    B: Send + 'static,
{
    match request.extract_parts::<AuthedUser>().await {
        Ok(_) => next.run(request).await,
        Err(status_code) => (status_code, Html(IndexTemplate {}.render().unwrap())).into_response(),
    }
}

impl Server {
    pub fn new() -> Self {
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
                    .layer(axum::middleware::from_fn(auth_middleware)), // .layer(axum::middleware::from_extractor::<AuthedUser>()),
            )
            .fallback(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Html(NotFoundTemplate {}.render().unwrap()),
                )
            })
            .layer(session_service)
            .layer(trace_layer)
            .nest_service("/static", routing::get_service(ServeDir::new("static")));

        Server { router: app }
    }

    pub async fn run(self, addr: std::net::SocketAddr) -> anyhow::Result<()> {
        axum::Server::bind(&addr)
            .serve(self.router.into_make_service())
            .await?;
        Ok(())
    }
}
