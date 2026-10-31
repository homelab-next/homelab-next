CREATE TABLE IF NOT EXISTS "authentication" (
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
    "user_name" TEXT NOT NULL,
    "src_endpoint" TEXT,
    "dst_endpoint" TEXT,
    "logon_type_id" INTEGER,
    "auth_protocol" TEXT,
    "is_mfa" INTEGER,
    "tlp" TEXT
);
