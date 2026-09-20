# 育肥猪场管理系统 - 后端服务

## 项目简介
育肥猪场管理系统的后端API服务，基于 Express + SQLite + JWT 构建。为前端应用提供数据存储、用户认证、业务管理等接口，支持跨设备数据同步。

## 功能特性
- 用户注册/登录（JWT认证）
- 多猪场管理，数据按用户隔离
- 批次管理（含多栋舍分配）
- 栋舍管理
- 饲料类型与饲料领用记录
- 药品疫苗目录与领用记录
- 存栏变动记录
- 收支记录与分类管理
- 待办任务管理
- 预警阈值配置
- 养殖阶段天数配置
- 全量数据同步接口
- SQLite / PostgreSQL 双数据库支持

## 技术栈
- Node.js 18+
- Express 5
- TypeScript
- SQLite (better-sqlite3)
- PostgreSQL (可选，pg)
- JWT (jsonwebtoken)
- bcryptjs

## 快速开始

### 安装依赖
```bash
npm install
```

### 开发模式
```bash
npm run server:dev
```
服务运行在 http://localhost:3001

### 编译并生产运行
```bash
npm run build:server
npm start
```

## 项目结构
```
pigfarm-server/
├── server/
│   ├── index.ts      # 后端入口（所有API路由）
│   └── db.ts         # 数据库抽象层（SQLite + PostgreSQL）
├── package.json
├── tsconfig.json
├── tsconfig.server.json
├── render.yaml       # Render 部署配置
├── DEPLOY.md         # 部署指南
└── README.md
```

## 部署
详见 [DEPLOY.md](./DEPLOY.md)，支持部署到 Render 等平台。

## API 文档
所有接口前缀为 `/api`，详见 DEPLOY.md 中的 API 接口概览。

### 认证接口
- `POST /api/auth/register` - 注册（自动创建示例数据）
- `POST /api/auth/login` - 登录
- `GET /api/auth/me` - 获取当前用户

### 健康检查
- `GET /api/health` - 服务健康状态

## 环境变量
| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PORT` | 3001 | 服务端口 |
| `NODE_ENV` | development | 运行环境 |
| `JWT_SECRET` | 随机生成 | JWT签名密钥 |
| `DB_PATH` | ./data/pigfarm.db | SQLite数据库文件路径 |
| `DATABASE_URL` | - | PostgreSQL连接串（设置后自动切换） |

## 数据库
默认使用 SQLite，数据文件存储在 `DB_PATH` 指定路径。

如需使用 PostgreSQL，设置 `DATABASE_URL` 环境变量即可自动切换。

## 许可证
MIT
