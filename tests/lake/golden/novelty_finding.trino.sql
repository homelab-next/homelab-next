CREATE TABLE IF NOT EXISTS "lake"."ocsf"."novelty_finding" (
    "uid" VARCHAR NOT NULL,
    "time" TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    "as_of" TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    "source" VARCHAR NOT NULL,
    "source_kind" VARCHAR NOT NULL,
    "profile" VARCHAR NOT NULL,
    "entity_kind" VARCHAR NOT NULL,
    "entity" VARCHAR NOT NULL,
    "entity_column" VARCHAR,
    "value" VARCHAR,
    "value_columns" ARRAY(VARCHAR),
    "status" VARCHAR NOT NULL,
    "score" DOUBLE,
    "confidence" DOUBLE,
    "support" DOUBLE,
    "entity_total" DOUBLE,
    "count" BIGINT,
    "learn_since" TIMESTAMP(6) WITH TIME ZONE,
    "learn_until" TIMESTAMP(6) WITH TIME ZONE,
    "score_since" TIMESTAMP(6) WITH TIME ZONE,
    "score_until" TIMESTAMP(6) WITH TIME ZONE,
    "spec_digest" VARCHAR,
    "message" VARCHAR,
    "reasons" ARRAY(VARCHAR),
    "tlp" VARCHAR
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['day(time)']
);
