use axum::{
    routing::{get, post, delete},
    Json, Router, extract::Path,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Clone)]
struct User {
    id: u32,
    name: String,
    email: String,
}

static mut USERS: Vec<User> = Vec::new();
static mut NEXT_ID: u32 = 1;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/users", get(get_users).post(create_user))
        .route("/users/:id", get(get_user).put(update_user).delete(delete_user))
        .route("/search", get(search_users));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn get_users() -> Json<serde_json::Value> {
    unsafe {
        Json(serde_json::json!({"items": USERS, "count": USERS.len()}))
    }
}

async fn get_user(Path(id): Path<u32>) -> Json<serde_json::Value> {
    unsafe {
        for user in &USERS {
            if user.id == id {
                return Json(serde_json::json!({"item": user}));
            }
        }
    }
    Json(serde_json::json!({"error": "Not found"}))
}

async fn create_user(Json(user): Json<User>) -> Json<serde_json::Value> {
    unsafe {
        let mut new_user = user.clone();
        new_user.id = NEXT_ID;
        NEXT_ID += 1;
        USERS.push(new_user.clone());
        Json(serde_json::json!({"item": new_user}))
    }
}

async fn update_user(Path(id): Path<u32>, Json(user): Json<User>) -> Json<serde_json::Value> {
    unsafe {
        for u in &mut USERS {
            if u.id == id {
                u.name = user.name.clone();
                u.email = user.email.clone();
                return Json(serde_json::json!({"item": u}));
            }
        }
    }
    Json(serde_json::json!({"error": "Not found"}))
}

async fn delete_user(Path(id): Path<u32>) -> Json<serde_json::Value> {
    unsafe {
        USERS.retain(|u| u.id != id);
    }
    Json(serde_json::json!({"message": "Deleted"}))
}

async fn search_users(axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>) -> Json<serde_json::Value> {
    let query = params.get("q").map(|s| s.as_str()).unwrap_or("");
    let mut results = Vec::new();
    unsafe {
        for user in &USERS {
            if user.name.contains(query) {
                results.push(user.clone());
            }
        }
    }
    Json(serde_json::json!({"results": results}))
}

fn unused_function() -> &'static str {
    "dead code"
}
