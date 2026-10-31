CREATE TABLE IF NOT EXISTS "lake"."ocsf"."dns_activity" (
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
    "src_endpoint" ROW("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR),
    "query_hostname" VARCHAR NOT NULL,
    "query_type" VARCHAR,
    "rcode_id" BIGINT,
    "answers" ARRAY(VARCHAR),
    "tlp" VARCHAR
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['day(time)']
);
