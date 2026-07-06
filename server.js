import express from 'express';
import { createServer } from 'node:http';
import rammerheadPkg from 'rammerhead';
import path from 'node:path';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'node:url';

const { RammerheadProxy } = rammerheadPkg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = createServer(app);

const PROXY_PASSWORD = 'mysecurepassword123';

// Rammerheadのセットアップ (ロガーを適切に設定)
const rammerhead = new RammerheadProxy({
    logger: {
        info: console.log,
        error: console.error,
        debug: console.log,
        traffic: () => {}, // ダミー関数を追加
    },
    reverseProxy: false,
    disableLocalStorageSync: false,
});

app.use(cookieParser());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 認証チェックミドルウェア
const authMiddleware = (req, res, next) => {
    if (req.cookies.proxy_auth === PROXY_PASSWORD) {
        next();
    } else {
        res.status(403).send('Forbidden: Please login at the root page.');
    }
};

app.post('/login', (req, res) => {
    if (req.body.password === PROXY_PASSWORD) {
        res.cookie('proxy_auth', PROXY_PASSWORD, { httpOnly: true, sameSite: 'lax' });
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false });
    }
});

// Rammerheadのリクエスト処理
app.use((req, res, next) => {
    if (req.url.startsWith('/ram/')) {
        return authMiddleware(req, res, () => {
            rammerhead.handleRequest(req, res);
        });
    }
    next();
});

server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/ram/')) {
        rammerhead.handleUpgrade(req, socket, head);
    } else {
        socket.end();
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Rammerhead Proxy running on port ${PORT}`);
});
