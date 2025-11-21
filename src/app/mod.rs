use leptos::{logging::log, prelude::*, server::codee::string::FromToStringCodec};
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    StaticSegment, components::{Route, Router, Routes}, hooks::use_navigate
};
use leptos_use::{SameSite, UseCookieOptions, use_cookie_with_options};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::api;

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
    use crate::auth::User;

    let state: crate::State = expect_context();

    let headers: HeaderMap = leptos_axum::extract().await?;
    let user_agent = headers
        .get("User-Agent").map(|v| v.to_str().unwrap().to_string())
        .or(user_agent)
        .ok_or(ServerFnError::new("no user agent found"))?;

    User::login(&state.pool, &state.key_store, &username, &password, &user_agent)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
async fn create_user(username: String, password: String, user_agent: Option<String>) -> Result<(String, String), ServerFnError> {
    use axum::http::HeaderMap;
    use crate::auth::User;

    let state: crate::State = expect_context();

    let headers: HeaderMap = leptos_axum::extract().await?;
    let user_agent = headers
        .get("User-Agent")
        .map(|v| v.to_str().unwrap().to_string())
        .or(user_agent)
        .ok_or(ServerFnError::new("no user agent found"))?;

    User::create(&state.pool, true, &username, &password).await.map_err(ServerFnError::new)?;
    User::login(&state.pool, &state.key_store, &username, &password, &user_agent)
        .await
        .map_err(ServerFnError::new)
}

#[component]
fn Login() -> impl IntoView {
    let ((_, set_jwt), (_, set_refresh_token)) = auth_cookies();

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
                            let password = password.get();
                            let username = username.get();
                            let navigate = use_navigate();
                            leptos::task::spawn_local(async move {
                                match login(username, password, None).await {
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
                                let password = password.get();
                                let username = username.get();
                                match create_user(username, password, None).await {
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
    let ((jwt, set_jwt), (refresh_token, set_refresh_token)) = auth_cookies();
    let navigate = use_navigate();

    let charts = Resource::new(|| (), |_| fetch_top_charts());

    Effect::new(move || {
        if jwt.get().is_none() {
            let refresh_token = refresh_token.clone();
            let n = use_navigate();
            leptos::task::spawn_local(async move {
                let base = web_sys::window().unwrap().location().origin().unwrap();
                let res = reqwest::Client::new()
                    .post(format!("{base}/auth/refresh"))
                    .bearer_auth(refresh_token.get_untracked().as_deref().unwrap())
                    .send()
                    .await
                    .unwrap();
                if res.status() == StatusCode::UNAUTHORIZED {
                    n("/login", Default::default());
                } else {
                    let (auth, refresh) = res.json::<(String, String)>().await.unwrap();
                    set_jwt.set(Some(auth.clone()));
                    set_refresh_token.set(Some(refresh));
                }
            });
        }
    });

    // Creates a reactive value to update the button
    let n = navigate.clone();
    let on_click = move |_| {
        let n = n.clone();
        let jwt = jwt.get();
        let refresh_token = refresh_token.get();
        leptos::task::spawn_local(async move {
            let base = web_sys::window().unwrap().location().origin().unwrap();
            let res = reqwest::Client::new()
                .get(format!("{base}/api/hello-world"))
                .bearer_auth(jwt.as_deref().unwrap_or_default())
                .send()
                .await
                .unwrap();

            if res.status() == StatusCode::UNAUTHORIZED {
                let res = reqwest::Client::new()
                    .post(format!("{base}/auth/refresh"))
                    .bearer_auth(refresh_token.as_deref().unwrap())
                    .send()
                    .await
                    .unwrap();
                if res.status() == StatusCode::UNAUTHORIZED {
                    n("/login", Default::default());
                } else {
                    let (auth, refresh) = res.json::<(String, String)>().await.unwrap();
                    set_jwt.set(Some(auth.clone()));
                    set_refresh_token.set(Some(refresh));
                    let res = reqwest::Client::new()
                        .get(format!("{base}/api/hello-world"))
                        .bearer_auth(auth)
                        .send()
                        .await
                        .unwrap();
                    log!("{}", res.text().await.unwrap());
                }
            } else {
                log!("{}", res.text().await.unwrap());
            }
        });
    };

    view! {
        <h1>"Welcome to Meloseerr!"</h1>
        <button on:click=on_click>"Click Me"</button>
        <Suspense>
            {move || {
                if let Some(Ok(charts)) = charts.get() {
                    view!{
                        <strong>Charts Loaded!</strong>
                        <h2>Albums</h2>
                        <div class="music-grid">
                        {move || {
                            charts.albums.data.iter()
                                .map(|album| {
                                    view! {
                                        <div style="display: flex; flex-direction: column; align-items: center">
                                            <div style="width: fit-content; height: fit-content" class="vinyl">
                                                <picture>
                                                    <source
                                                     srcset={album.cover.clone()}
                                                     media="(max-width: 576px)"
                                                    />
                                                    <image src={album.cover_medium.clone()} alt="cover" style="border-radius: 50%" />
                                                </picture>
                                                <div></div>
                                                <div></div>
                                            </div>
                                            <div style="display: flex; flex-direction: column; width: 100%; align-items: start">
                                                <span>{album.title.clone()}</span>
                                            </div>
                                        </div>
                                    }
                                })
                                .collect_view()
                        }}
                        </div>
                        <h2>Artists</h2>
                        <div class="music-grid">
                        {move || {
                            charts.artists.data.iter()
                                .map(|artist| {
                                    view! {
                                        <div style="display: flex; flex-direction: column; align-items: center">
                                            <div style="width: fit-content; height: fit-content">
                                                <picture>
                                                    <source srcset={artist.picture.clone()} media="(max-width: 576px)" />
                                                    <image src={artist.picture_medium.clone()} alt="cover" style="border-radius: 100%" />
                                                </picture>
                                            </div>
                                            <div style="display: flex; flex-direction: column; width: 100%; align-items: start">
                                                <span>{artist.name.clone()}</span>
                                            </div>
                                        </div>
                                    }
                                })
                                .collect_view()
                        }}
                        </div>
                        <h2>Tracks</h2>
                        <div class="music-grid">
                        {move || {
                            charts.tracks.data.iter()
                                .map(|track| {
                                    view! {
                                        <div style="display: flex; flex-direction: column; align-items: center">
                                            <div style="width: fit-content; height: fit-content">
                                                <picture>
                                                    <source
                                                     srcset={format!("https://e-cdns-images.dzcdn.net/images/cover/{}/120x120.jpg", track.md5_image)}
                                                     media="(max-width: 576px)"
                                                    />
                                                    <image src={format!("https://e-cdns-images.dzcdn.net/images/cover/{}/250x250.jpg", track.md5_image)} alt="cover" />
                                                </picture>
                                            </div>
                                            <div style="display: flex; flex-direction: column; width: 100%; align-items: start">
                                                <span>{track.title.clone()}</span>
                                                <span>{track.duration / 60}:{track.duration % 60}</span>
                                                <span>{track.rank}</span>
                                                <span>{track.explicit_lyrics}</span>
                                            </div>
                                        </div>
                                    }
                                })
                                .collect_view()
                        }}
                        </div>
                    }
                        .into_any()
                } else {
                    view!{ <strong>Charts Not Loaded!</strong> }
                        .into_any()
                }
            }}
        </Suspense>
    }
}

fn auth_cookies() -> (
    (Signal<Option<String>>, WriteSignal<Option<String>>),
    (Signal<Option<String>>, WriteSignal<Option<String>>)
) {
    (
        use_cookie_with_options::<String, FromToStringCodec>(
            "MELOSEERR_JWT",
            UseCookieOptions::default()
                .max_age(chrono::Duration::minutes(30).num_milliseconds())
                .same_site(SameSite::Lax)
        ),
        use_cookie_with_options::<String, FromToStringCodec>(
            "MELOSEERR_REFRESH_TOKEN",
            UseCookieOptions::default()
                .max_age(chrono::Duration::days(14).num_milliseconds())
                .same_site(SameSite::Lax)
        )
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Charts {
    pub tracks: DeezerPage<Track>,
    pub albums: DeezerPage<Album>,
    pub artists: DeezerPage<Artist>,
    pub podcasts: DeezerPage<Podcast>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DeezerPage<T> {
    pub data: Vec<T>,
    pub total: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Track {
    pub id: usize,
    pub title: String,
    pub link: String,
    pub duration: usize,
    pub rank: usize,
    pub explicit_lyrics: bool,
    pub md5_image: String,
    pub artist: Artist,
    pub album: Album,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Artist {
    pub id: usize,
    pub name: String,
    pub link: String,
    pub picture: String,
    pub picture_small: String,
    pub picture_medium: String,
    pub picture_big: String,
    pub picture_xl: String,
    pub radio: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Album {
    pub id: usize,
    pub title: String,
    pub cover: String,
    pub cover_small: String,
    pub cover_medium: String,
    pub cover_big: String,
    pub cover_xl: String,
    pub md5_image: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Podcast {
    pub id: usize,
    pub title: String,
    pub description: String,
    pub available: bool,
    pub fans: usize,
    pub link: String,
    pub share: String,

    pub picture: String,
    pub picture_small: String,
    pub picture_medium: String,
    pub picture_big: String,
    pub picture_xl: String,
}

#[server]
async fn fetch_top_charts() -> Result<Charts, ServerFnError> {
    let charts = reqwest::get("https://api.deezer.com/chart?limit=10")
        .await
        .map_err(ServerFnError::new)?
        .json::<Charts>()
        .await
        .map_err(ServerFnError::new)?;

    Ok(charts)
}