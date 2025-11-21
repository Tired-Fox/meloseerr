use leptos::{prelude::*, server::codee::string::FromToStringCodec, server_fn::error::NoCustomError};
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    NavigateOptions, StaticSegment, components::{Route, Router, Routes}, hooks::use_navigate
};
use leptos_use::use_cookie;

use crate::{api, auth::User};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/server.css"/>

        // sets the document title
        <Title text="Welcome to Leptos"/>

        // content for this welcome page
        <Router>
            <main>
                <Routes fallback=|| "Page not found.".into_view()>
                    <Route path=StaticSegment("") view=HomePage/>
                    <Route path=StaticSegment("login") view=Login/>
                </Routes>
            </main>
        </Router>
    }
}

#[server]
async fn login(username: String, password: String, user_agent: Option<String>) -> Result<(String, String), ServerFnError> {
    use axum::http::HeaderMap;

    let state: crate::State = expect_context();

    let headers: HeaderMap = leptos_axum::extract().await?;
    let user_agent = headers
        .get("User-Agent").map(|v| v.to_str().unwrap().to_string())
        .or(user_agent)
        .ok_or(ServerFnError::new("no user agent found"))?;

    User::login(&state.pool, &state.key_store, &username, &password, &user_agent)
        .await
        .map_err(|e| ServerFnError::ServerError(e.to_string()))
}

#[server]
async fn create_user(username: String, password: String, user_agent: Option<String>) -> Result<(String, String), ServerFnError> {
    use axum::http::HeaderMap;

    let state: crate::State = expect_context();

    let headers: HeaderMap = leptos_axum::extract().await?;
    let user_agent = headers
        .get("User-Agent")
        .map(|v| v.to_str().unwrap().to_string())
        .or(user_agent)
        .ok_or(ServerFnError::new("no user agent found"))?;

    User::create(&state.pool, true, &username, &password).await.map_err(|err| ServerFnError::new(err))?;
    User::login(&state.pool, &state.key_store, &username, &password, &user_agent)
        .await
        .map_err(|err| ServerFnError::ServerError(err.to_string()))
}

#[component]
fn Login() -> impl IntoView {
    let (jwt, set_jwt) = use_cookie::<String, FromToStringCodec>("MOLESEER_JWT");
    let (refresh_token, set_refresh_token) = use_cookie::<String, FromToStringCodec>("MOLESEER_REFRESH_TOKEN");

    let users = OnceResource::new(api::user_count());

    let (error, set_error) = signal(None);
    let username = RwSignal::new("".to_string());
    let password = RwSignal::new("".to_string());

    view! {
        <h1>Login</h1>
        <Suspense fallback=move || view! {}>
            { move || {
                if users.get().as_ref().map(|v| v.clone().unwrap_or_default()).unwrap_or_default() > 0 {
                    view! {
                        <div>
                            <label for="username">Username</label>
                            <input id="username" type="text" bind:value=username />
                        </div>
                        <div>
                            <label for="password">Password</label>
                            <input id="password" type="password" bind:value=password />
                        </div>
                        <button on:click=move |_| {
                            set_error.set(None);
                            leptos::task::spawn_local(async move {
                                let navigate = use_navigate();
                                match login(username.get(), password.get(), None).await {
                                    Ok((auth, refresh)) => {
                                        set_jwt.set(Some(auth));
                                        set_refresh_token.set(Some(refresh));
                                        navigate("/", Default::default())
                                    },
                                    Err(err) => set_error.set(Some(err.to_string()))
                                }
                            })
                        }>Login</button>
                    }.into_any()
                } else {
                    view!{
                        <p>Admin Profile</p>
                        <div>
                            <label for="username">Username</label>
                            <input id="username" type="text" bind:value=username />
                        </div>
                        <div>
                            <label for="password">Password</label>
                            <input id="password" type="password" bind:value=password />
                        </div>
                        <button on:click=move |_| {
                            set_error.set(None);
                            leptos::task::spawn_local(async move {
                                let navigate = use_navigate();
                                match create_user(username.get(), password.get(), None).await {
                                    Ok((auth, refresh)) => {
                                        set_jwt.set(Some(auth));
                                        set_refresh_token.set(Some(refresh));
                                        navigate("/", Default::default())
                                    },
                                    Err(err) => set_error.set(Some(err.to_string()))
                                }
                            })
                        }>
                            Create Admin User
                        </button>
                    }.into_any()
                }
            }}
        </Suspense>
        <Show when=move || error.get().is_some()>
            {error}
        </Show>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let (jwt, _) = use_cookie::<String, FromToStringCodec>("MELOSEERR_JWT");
    let navigate = use_navigate();

    Effect::new(move || {
        println!("Hello, world!");
        if jwt.get().is_none() {
            navigate("/login", NavigateOptions::default());
        }
    });

    // Creates a reactive value to update the button
    let count = RwSignal::new(0);
    let on_click = move |_| *count.write() += 1;

    view! {
        <h1>"Welcome to Leptos!"</h1>
        <button on:click=on_click>"Click Me: " {count}</button>
    }
}
