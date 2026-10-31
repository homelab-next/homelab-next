CREATE TABLE IF NOT EXISTS "authentication" (
    "uid" VARCHAR NOT NULL,
    "time" TIMESTAMP NOT NULL,
    "class_uid" BIGINT NOT NULL,
    "category_uid" BIGINT NOT NULL,
    "activity_id" BIGINT NOT NULL,
    "type_uid" BIGINT,
    "severity_id" BIGINT NOT NULL,
    "status_id" BIGINT,
    "message" VARCHAR,
    "metadata" STRUCT("version" VARCHAR, "product" VARCHAR, "log_source" VARCHAR),
    "user_name" VARCHAR NOT NULL,
    "src_endpoint" STRUCT("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR),
    "dst_endpoint" STRUCT("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR),
    "logon_type_id" BIGINT,
    "auth_protocol" VARCHAR,
    "is_mfa" BOOLEAN,
    "tlp" VARCHAR
);
