//! Account and OPAQUE credential-record persistence. Ported from the Bun
//! reference's `auth/credentials.mjs`; queries are runtime-checked
//! (`sqlx::query`) rather than compile-time `query!` macros, matching this
//! module's use of a shared executor type across both a pool and an
//! in-transaction client.

use sqlx::{Executor, Postgres};

pub async fn ensure_account<'e, E>(executor: E, account_id: &str) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("INSERT INTO accounts (account_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(account_id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn get_credential_record<'e, E>(
    executor: E,
    account_id: &str,
) -> Result<Option<Vec<u8>>, sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT credential_record FROM opaque_credentials WHERE account_id = $1")
            .bind(account_id)
            .fetch_optional(executor)
            .await?;
    Ok(row.map(|(record,)| record))
}

/// Stores the credential record the first time an account registers.
/// Re-registration is a silent no-op (the existing record is kept) so the
/// response shape never reveals whether an account already had credentials.
pub async fn save_credential_record_if_absent<'e, E>(
    executor: E,
    account_id: &str,
    record: &[u8],
) -> Result<(), sqlx::Error>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO opaque_credentials (account_id, credential_record) VALUES ($1, $2) \
         ON CONFLICT (account_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(record)
    .execute(executor)
    .await?;
    Ok(())
}
