use crate::db;
use crate::util::hash_password;
use sqlx::SqlitePool;

/// rust_proxy_admin reset-password --username admin --password 'NewPass123!'
pub async fn reset_password(db_url: &str, username: &str, password: &str) -> anyhow::Result<()> {
    if password.len() < 8 {
        anyhow::bail!("新密码至少 8 位");
    }
    let pool: SqlitePool = db::connect(db_url).await?;
    db::migrate(&pool).await?;
    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&pool)
            .await?;
    let Some((uid,)) = exists else {
        anyhow::bail!("用户 {username} 不存在");
    };
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(hash_password(password)?)
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    // 旧会话全部失效
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    println!("用户 {username} 的密码已重置，旧会话已全部失效");
    Ok(())
}
