CREATE TABLE IF NOT EXISTS "network_activity" (
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
    "src_endpoint" STRUCT("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR) NOT NULL,
    "dst_endpoint" STRUCT("ip" VARCHAR, "port" BIGINT, "hostname" VARCHAR) NOT NULL,
    "protocol_name" VARCHAR,
    "connection_uid" VARCHAR,
    "direction_id" BIGINT,
    "bytes_in" BIGINT,
    "bytes_out" BIGINT
);
