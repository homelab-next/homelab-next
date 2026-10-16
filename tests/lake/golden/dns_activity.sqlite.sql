CREATE TABLE IF NOT EXISTS "dns_activity" (
    "uid" TEXT NOT NULL,
    "time" TEXT NOT NULL,
    "class_uid" INTEGER NOT NULL,
    "category_uid" INTEGER NOT NULL,
    "activity_id" INTEGER NOT NULL,
    "type_uid" INTEGER,
    "severity_id" INTEGER NOT NULL,
    "status_id" INTEGER,
    "message" TEXT,
    "metadata" TEXT,
    "src_endpoint" TEXT,
    "query_hostname" TEXT NOT NULL,
    "query_type" TEXT,
    "rcode_id" INTEGER,
    "answers" TEXT
);
