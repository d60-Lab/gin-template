-- 创建数据库
CREATE DATABASE gin_template;
-- 连接到数据库
\ c gin_template;
-- 用户表会由 GORM 自动创建，这里是参考结构
-- CREATE TABLE users (
--     id VARCHAR(36) PRIMARY KEY,
--     username VARCHAR(50) UNIQUE NOT NULL,
--     email VARCHAR(100) UNIQUE NOT NULL,
--     password VARCHAR(255) NOT NULL,
--     age INT,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     deleted_at TIMESTAMP
-- );
-- 创建索引
-- CREATE INDEX idx_users_deleted_at ON users(deleted_at);
-- CREATE UNIQUE INDEX idx_users_username ON users(username);
-- CREATE UNIQUE INDEX idx_users_email ON users(email);