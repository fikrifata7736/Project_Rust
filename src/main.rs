use actix_web::{web, App, HttpServer, HttpResponse, Responder, post, get, middleware};
use actix_files::Files;
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref USERS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

#[derive(Deserialize)]
struct AuthData {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct UserResponse {
    email: String,
}

// login page
#[get("/login")]
async fn login_page() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/login.html"))
}

// Handle Login 
#[post("/auth/login")]
async fn login(data: web::Json<AuthData>) -> impl Responder {
    let users = USERS.lock().unwrap();
    
    if let Some(stored_hash) = users.get(&data.email) {
        if verify(&data.password, stored_hash).unwrap_or(false) {
            return HttpResponse::Ok().json(UserResponse { 
                email: data.email.clone() 
            });
        }
    }
    
    HttpResponse::Unauthorized().json(web::Json(serde_json::json!({
        "error": "Invalid email or password"
    })))
}

// Registration Page
#[get("/register")]
async fn register_page() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/register.html"))
}

//API 
#[post("/auth/register")]
async fn register(data: web::Json<AuthData>) -> impl Responder {
    let hashed = match hash(&data.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(web::Json(serde_json::json!({
            "error": "Failed to hash password"
        }))),
    };
    
    let mut users = USERS.lock().unwrap();
    if users.contains_key(&data.email) {
        return HttpResponse::BadRequest().json(web::Json(serde_json::json!({
            "error": "Email already exists"
        })));
    }
    
    users.insert(data.email.clone(), hashed);
    
    HttpResponse::Ok().json(web::Json(serde_json::json!({
        "message": "User registered successfully"
    })))
}

// Redirect login page
#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Found()
        .append_header(("Location", "/login"))
        .finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server running at http://127.0.0.1:3000");
    
    HttpServer::new(|| {
        App::new()
            // Enable debugging
            .wrap(middleware::Logger::default())
            // Routes
            .service(index)
            .service(login_page)
            .service(login)
            .service(register_page)
            .service(register)
            // Serve static files (CSS, JS, images)
            .service(Files::new("/static", "./static").show_files_listing())
            // This is important for Bootstrap files if you want to serve them locally
            .service(Files::new("/css", "./static/css"))
            .service(Files::new("/js", "./static/js"))
    })
    .bind("127.0.0.1:3000")?
    .run()
    .await
}