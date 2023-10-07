use askama::Template;
use axum::{
    response::{Html, IntoResponse},
    routing::{self, get, post},
    Form, Router,
};
use axum_sessions::{
    async_session,
    extractors::{ReadableSession, WritableSession},
    SessionLayer,
};
use serde::Deserialize;
use tower::ServiceBuilder;
use tower_http::{services::ServeDir, trace::TraceLayer};

pub struct Server {
    router: Router<()>,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_post(
    mut sess: WritableSession,
    Form(login): Form<LoginForm>,
) -> axum::response::Response {
    tracing::info!("stuff we got: {login:?}");
    sess.insert_raw("username", format!("{}-{}", login.username, login.password));

    axum::response::Redirect::to("/").into_response()
}

impl Server {
    pub fn new() -> Self {
        let trace_layer = ServiceBuilder::new().layer(TraceLayer::new_for_http());
        let store = async_session::MemoryStore::new();
        let secret = b"c20d16e16b32c77f63bc42d7565a75026211cb67f34d77553091761cba16943bbb51c1bcbd8fc08ee23e010407e49fa5f5b516f0625d247bc436c3938debf71c";
        let secret = hex::decode(secret).unwrap();

        let session_layer = SessionLayer::new(store, &secret);

        let app = Router::new()
            .layer(trace_layer)
            .layer(session_layer)
            .route(
                "/",
                get(|| async {
                    let tpl = IndexTemplate {};
                    Html(tpl.render().unwrap())
                }),
            )
            .route("/login", post(login_post))
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
