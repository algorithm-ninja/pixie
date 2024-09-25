use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use axum::{
    extract::{
        self,
        ws::{self, Message},
        Path,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use macaddr::MacAddr6;

use pixie_shared::{HttpConfig, WsUpdate};
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer, services::ServeDir, trace::TraceLayer,
    validate_request::ValidateRequestHeaderLayer,
};

use crate::state::State;

async fn action(
    Path((unit_filter, action_name)): Path<(String, String)>,
    extract::State(state): extract::State<Arc<State>>,
) -> impl IntoResponse {
    let Ok(action) = action_name.parse() else {
        return (
            StatusCode::BAD_REQUEST,
            format!("Unknown action: {:?}\n", action_name),
        );
    };

    let mut updated = 0usize;

    state.units.send_if_modified(|units| {
        if let Ok(mac) = unit_filter.parse::<MacAddr6>() {
            for unit in units.iter_mut() {
                if unit.mac == mac {
                    unit.next_action = action;
                    updated += 1;
                }
            }
        } else if let Ok(ip) = unit_filter.parse::<Ipv4Addr>() {
            for unit in units.iter_mut() {
                if unit.static_ip() == ip {
                    unit.next_action = action;
                    updated += 1;
                }
            }
        } else if unit_filter == "all" {
            for unit in units.iter_mut() {
                unit.next_action = action;
                updated += 1;
            }
        } else if let Some(&group) = state.config.groups.get_by_first(&unit_filter) {
            for unit in units.iter_mut() {
                if unit.group == group {
                    unit.next_action = action;
                    updated += 1;
                }
            }
        } else if state.config.images.contains(&unit_filter) {
            for unit in units.iter_mut() {
                if unit.image == unit_filter {
                    unit.next_action = action;
                    updated += 1;
                }
            }
        }

        updated > 0
    });

    if updated > 0 {
        (StatusCode::OK, format!("{updated} computer(s) affected\n"))
    } else {
        (StatusCode::BAD_REQUEST, "Unknown PC\n".to_owned())
    }
}

async fn image(
    Path((unit_filter, image)): Path<(String, String)>,
    extract::State(state): extract::State<Arc<State>>,
) -> impl IntoResponse {
    if !state.config.images.contains(&image) {
        return (
            StatusCode::BAD_REQUEST,
            format!("Unknown image: {:?}\n", image),
        );
    }

    let mut updated = 0usize;

    state.units.send_if_modified(|units| {
        if let Ok(mac) = unit_filter.parse::<MacAddr6>() {
            for unit in units.iter_mut() {
                if unit.mac == mac {
                    unit.image = image.clone();
                    updated += 1;
                }
            }
        } else if let Ok(ip) = unit_filter.parse::<Ipv4Addr>() {
            for unit in units.iter_mut() {
                if unit.static_ip() == ip {
                    unit.image = image.clone();
                    updated += 1;
                }
            }
        } else if unit_filter == "all" {
            for unit in units.iter_mut() {
                unit.image = image.clone();
                updated += 1;
            }
        } else if let Some(&group) = state.config.groups.get_by_first(&unit_filter) {
            for unit in units.iter_mut() {
                if unit.group == group {
                    unit.image = image.clone();
                    updated += 1;
                }
            }
        } else if state.config.images.contains(&unit_filter) {
            for unit in units.iter_mut() {
                if unit.image == unit_filter {
                    unit.image = image.clone();
                    updated += 1;
                }
            }
        }

        updated > 0
    });

    if updated > 0 {
        (StatusCode::OK, format!("{updated} computer(s) affected\n"))
    } else {
        (StatusCode::BAD_REQUEST, "Unknown PC\n".to_owned())
    }
}

async fn gc(extract::State(state): extract::State<Arc<State>>) -> String {
    state.gc_chunks().await.unwrap();
    "".to_owned()
}

async fn ws(
    extract::State(state): extract::State<Arc<State>>,
    ws: extract::ws::WebSocketUpgrade,
) -> axum::response::Response {
    ws.on_upgrade(move |mut socket| async move {
        let msg = WsUpdate::Config(state.config.clone());
        let msg = serde_json::to_string(&msg).unwrap();
        let msg = Message::Text(msg);
        socket.send(msg).await.unwrap();

        let msg = WsUpdate::HostMap(state.hostmap.clone());
        let msg = serde_json::to_string(&msg).unwrap();
        let msg = Message::Text(msg);
        socket.send(msg).await.unwrap();

        let mut units_rx = state.units.subscribe();
        units_rx.mark_changed();

        let mut image_rx = state.image_stats.subscribe();
        image_rx.mark_changed();

        'main_loop: loop {
            tokio::select! {
                ret = units_rx.changed() => {
                    ret.unwrap();
                    let msg = {
                        let units = units_rx.borrow_and_update();
                        let msg = WsUpdate::Units(units.clone());
                        let msg = serde_json::to_string(&msg).unwrap();
                        ws::Message::Text(msg)
                    };
                    socket.send(msg).await.unwrap();
                }
                ret = image_rx.changed() => {
                    ret.unwrap();
                    let msg = {
                        let image_stats = image_rx.borrow_and_update();
                        let msg = WsUpdate::ImageStats(image_stats.clone());
                        let msg = serde_json::to_string(&msg).unwrap();
                        ws::Message::Text(msg)
                    };
                    socket.send(msg).await.unwrap();
                }
                packet = socket.recv() => {
                    let packet = packet.unwrap().unwrap();
                    if let Message::Close(_) = packet {
                        break 'main_loop;
                    }
                }
            };

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
}

pub async fn main(state: Arc<State>) -> Result<()> {
    let HttpConfig {
        listen_on,
        ref password,
    } = state.config.http;

    let admin_path = state.storage_dir.join("admin");

    let router = Router::new()
        .route("/admin/ws", get(ws))
        .route("/admin/gc", get(gc))
        .route("/admin/action/:unit/:action", get(action))
        .route("/admin/image/:unit/:image", get(image))
        .nest_service(
            "/",
            ServeDir::new(&admin_path).append_index_html_on_directories(true),
        )
        .layer(CompressionLayer::new())
        .layer(ValidateRequestHeaderLayer::basic("admin", password))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = TcpListener::bind(listen_on).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
