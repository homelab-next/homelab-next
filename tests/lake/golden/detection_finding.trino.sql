CREATE TABLE IF NOT EXISTS "lake"."ocsf"."detection_finding" (
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
    "finding_uid" VARCHAR NOT NULL,
    "finding_title" VARCHAR,
    "detection_id" VARCHAR NOT NULL,
    "risk_score" BIGINT,
    "confidence_id" BIGINT,
    "attack_techniques" ARRAY(VARCHAR),
    "host_name" VARCHAR
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['day(time)']
);
