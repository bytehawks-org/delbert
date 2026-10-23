-- Development only: the runtime login role used by the Core (member of delbert_app,
-- which the migrations create if missing). In production create it with a real secret.
CREATE ROLE delbert_app NOLOGIN;
CREATE ROLE delbert_rt LOGIN PASSWORD 'delbert-rt-dev' IN ROLE delbert_app;
