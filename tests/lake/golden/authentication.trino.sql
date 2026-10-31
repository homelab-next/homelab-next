CREATE TABLE IF NOT EXISTS "lake"."ocsf"."authentication" (
    "uid" VARCHAR NOT NULL,
    "time" TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    "class_uid" BIGINT NOT NULL,
    "category_uid" BIGINT NOT NULL,
    "activity_id" BIGINT NOT NULL,
    "type_uid" BIGINT,
    "severity_id" BIGINT NOT NULL,
    "status_id" BIGINT,
    "message" VARCHAR,
    "metadata" ROW("version" VARCHAR, "product" VARCHAR, "log_source" VARCHAR),
    "user_name" VARCHAR NOT NULL,
    "src_endpoint" ROW("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR),
    "dst_endpoint" ROW("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR),
    "logon_type_id" BIGINT,
    "auth_protocol" VARCHAR,
    "is_mfa" BOOLEAN,
    "tlp" VARCHAR
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['day(time)']
);
