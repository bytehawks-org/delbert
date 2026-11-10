#!/bin/sh
# Runs once, when the PostgreSQL volume is created: the runtime login of the Core. It is a
# member of delbert_app, which gets no UPDATE/DELETE on the audit trail and policy versions.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v rt_password="$DELBERT_RT_PASSWORD" <<'SQL'
CREATE ROLE delbert_app NOLOGIN;
CREATE ROLE delbert_rt LOGIN PASSWORD :'rt_password' IN ROLE delbert_app;
SQL
