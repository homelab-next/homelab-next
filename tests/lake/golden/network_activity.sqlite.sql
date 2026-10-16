CREATE TABLE IF NOT EXISTS "network_activity" (
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
    "src_endpoint" TEXT NOT NULL,
    "dst_endpoint" TEXT NOT NULL,
    "protocol_name" TEXT,
    "connection_uid" TEXT,
    "direction_id" INTEGER,
    "bytes_in" INTEGER,
    "bytes_out" INTEGER
);
