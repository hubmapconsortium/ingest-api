CREATE TABLE IF NOT EXISTS logs (
    `id`                bigint(20)                          NOT NULL AUTO_INCREMENT,
    `app_name`          varchar(255)                        NOT NULL,
    `log_level`         enum('info', 'warn', 'error', 'fatal')       NOT NULL,
    `page_path`         text                                DEFAULT NULL,
    `message`           text                                DEFAULT NULL,
    `error_details`     text                                DEFAULT NULL,
    `client_ip`         varchar(255)                        NOT NULL,
    `browser_info`      text                                DEFAULT NULL,
    `timestamp`         timestamp                           NOT NULL DEFAULT current_timestamp(),
    PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;