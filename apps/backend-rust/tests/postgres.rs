use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use zkpm_backend_poc::{app, config::Config, pool};

#[tokio::test]
#[ignore = "requires dedicated local PostgreSQL; run explicitly with --ignored"]
async fn real_postgres_readiness_and_transaction_rollback() {
    let url = std::env::var("POC_TEST_DATABASE_URL").expect("POC_TEST_DATABASE_URL is required");
    let config = Config::from_values(None, Some(url)).unwrap();
    let pool = pool(&config).unwrap();
    let response = app(pool.clone())
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Connection-local temporary table only; no application schema/data touched.
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("CREATE TEMP TABLE rust01_probe (value INTEGER NOT NULL)")
        .execute(&mut *connection)
        .await
        .unwrap();
    {
        use sqlx::Acquire;
        let mut tx = connection.begin().await.unwrap();
        sqlx::query("INSERT INTO rust01_probe(value) VALUES ($1)")
            .bind(7_i32)
            .execute(&mut *tx)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rust01_probe")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 1);
        tx.rollback().await.unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rust01_probe")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(count, 0);
    drop(connection);
    pool.close().await;
    let response = app(pool)
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
