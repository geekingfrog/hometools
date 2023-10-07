use askama::Template;
use axum::{
    async_trait,
    error_handling::HandleErrorLayer,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse},
    routing::{self, get, post},
    BoxError, Form, Router,
};

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
        tracing::info!("COUCOU extracting here!");

        let sess = parts.extract::<Session>().await.expect("got the session");

        tracing::info!("COUCOU got session!");
        let user = sess
            .get("user")
            .unwrap_or(None)
            .ok_or(StatusCode::UNAUTHORIZED)?;
        tracing::info!("COUCOU got user! {:?}", sess);

        Ok(user)
    }
}

async fn root_post(
    mut sess: Session,
    stuff: Option<AuthedUser>,
    Form(login): Form<LoginForm>,
) -> axum::response::Response {
    // tracing::debug!("got stuff from session: {:?}", sess.get_raw("username"));
    // tracing::debug!("authed user? {:?}", stuff);
    // sess.insert_raw("username", format!("{}-{}", login.username, login.password));
    sess.insert(
        "user",
        AuthedUser {
            username: login.username,
        },
    )
    .unwrap();

    axum::response::Redirect::to("/").into_response()
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
            .layer(trace_layer)
            .route(
                "/",
                get(|| async {
                    let tpl = IndexTemplate {};
                    Html(tpl.render().unwrap())
                })
                .post(root_post),
            )
            .route(
                "/tools",
                get(|| async { Html(ToolsTemplate {}.render().unwrap()) }),
            )
            .layer(session_service)
            .fallback(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Html(NotFoundTemplate {}.render().unwrap()),
                )
            })
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
