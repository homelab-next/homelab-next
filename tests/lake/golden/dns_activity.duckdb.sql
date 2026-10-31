CREATE TABLE IF NOT EXISTS "dns_activity" (
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
    "src_endpoint" STRUCT("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR),
    "query_hostname" VARCHAR NOT NULL,
    "query_type" VARCHAR,
    "rcode_id" BIGINT,
    "answers" VARCHAR[],
    "tlp" VARCHAR
);
