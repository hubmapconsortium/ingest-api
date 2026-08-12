
CREATE DATABASE IF NOT EXISTS bulk_register_db
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_0900_ai_ci;
 
USE bulk_register_db;
CREATE TABLE IF NOT EXISTS users (
    `globus_id`        varchar(64)  NOT NULL,
    `name`             varchar(255)          DEFAULT NULL,
    `email`            varchar(255)          DEFAULT NULL,
    `created_at`       timestamp    NOT NULL DEFAULT current_timestamp(),
    PRIMARY KEY (`globus_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
 
CREATE TABLE IF NOT EXISTS batches (
    `batch_id`         varchar(64)  NOT NULL,
    `temp_id`          varchar(255)          DEFAULT NULL,
    `total_jobs`       int(11)      NOT NULL,
    `success_count`    int(11)      NOT NULL DEFAULT 0,
    `failed_count`     int(11)      NOT NULL DEFAULT 0,
    `status`           enum('running','success','failed','partial')
                                    NOT NULL,
    `created_at`       timestamp    NOT NULL DEFAULT current_timestamp(),
    `completed_at`     timestamp             DEFAULT NULL,
    `group_uuid`       varchar(64)           DEFAULT NULL,
    `parent_batch_id`  varchar(32)           DEFAULT NULL,
    `entity_type`      varchar(16)           DEFAULT NULL,
    `globus_id`        varchar(64)           DEFAULT NULL,
    PRIMARY KEY (`batch_id`),
    CONSTRAINT `fk_batches_user` FOREIGN KEY (`globus_id`) REFERENCES `users` (`globus_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
 
CREATE TABLE IF NOT EXISTS jobs (
    `id`            bigint(20)   NOT NULL AUTO_INCREMENT,
    `batch_id`      varchar(64)  NOT NULL,
    `internal_id`   varchar(255) NOT NULL,
    `entity_uuid`   char(36)              DEFAULT NULL,
    `hubmap_id`     varchar(64)           DEFAULT NULL,
    `status`        enum('success','failed') NOT NULL,
    `error_detail`  text                  DEFAULT NULL,
    `completed_at`  timestamp    NOT NULL DEFAULT current_timestamp(),
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_batch_internal` (`batch_id`,`internal_id`),
    CONSTRAINT `fk_jobs_batch` FOREIGN KEY (`batch_id`) REFERENCES `batches` (`batch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
