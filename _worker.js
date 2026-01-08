// _worker.js - 终极防御版
// 1. Docker Hub 强制鉴权 (防429)
// 2. 多路镜像仓库支持
// 3. 首页伪装 Nginx
// 4. [新增] 反爬虫、反AI、反扫描机制

const HUB_HOST = 'registry-1.docker.io';
const AUTH_URL = 'https://auth.docker.io';

// 路由定义
const ROUTES = {
    "quay": "quay.io",
    "gcr": "gcr.io",
    "k8s-gcr": "k8s.gcr.io",
    "k8s": "registry.k8s.io",
    "ghcr": "ghcr.io",
    "cloudsmith": "docker.cloudsmith.io",
    "nvcr": "nvcr.io",
    "test": "registry-1.docker.io",
};

// =========================================================
// 安全配置：黑名单定义
// =========================================================

// 1. 被屏蔽的 User-Agent 关键词 (全部转小写匹配)
// 包含：AI爬虫, SEO工具, 漏洞扫描器, 常见通用爬虫
const BLOCKED_AGENTS = [
    'netcraft', 'zgrab', 'survey', 'indie', // 扫描器
    'gptbot', 'chatgpt', 'claudebot', 'anthropic', 'facebookexternalhit', // AI & 社交
    'semrush', 'ahrefs', 'dotbot', 'mj12bot', 'bingbot', 'googlebot', 'yandex', 'baiduspider', // SEO & 搜索
    'python-requests', 'curl', 'wget' // 通用工具 (谨慎：如果你自己用curl测试，请注释掉这行)
];

// 2. 被屏蔽的路径关键词 (防止敏感文件扫描)
const BLOCKED_PATHS = [
    '.env', '.git', '.aws', '.ds_store', // 配置文件
    'wp-admin', 'wp-login', 'phpmyadmin', // CMS后台
    'actuator', 'swagger', 'api-docs' // 探测接口
];

// Nginx 伪装页面
function getNginxHtml() {
    return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();

    // =========================================================
    // 防御层 1：Robots.txt (君子协议)
    // =========================================================
    if (url.pathname === '/robots.txt') {
        return new Response("User-agent: *\nDisallow: /", { status: 200 });
    }

    // =========================================================
    // 防御层 2：反扫描与反爬虫 (拦截恶意 UA 和 路径)
    // =========================================================
    
    // 检查 UA 是否在黑名单中 (排除正常的 Docker 客户端)
    // Docker 客户端通常包含 "docker" 或 "containerd"
    const isDockerClient = ua.includes('docker') || ua.includes('containerd') || ua.includes('buildkit');
    
    const isBlockedUA = BLOCKED_AGENTS.some(agent => ua.includes(agent));
    const isBlockedPath = BLOCKED_PATHS.some(path => url.pathname.includes(path));

    // 如果是黑名单 UA 且不是 Docker 客户端，或者访问了敏感路径
    // 直接返回 Nginx 伪装页，让对方以为这里只是个普通的静态网页
    if ((isBlockedUA && !isDockerClient) || isBlockedPath) {
        return new Response(getNginxHtml(), {
            status: 200, // 返回 200 迷惑扫描器，让它以为页面存在但只是普通内容
            headers: { 'Content-Type': 'text/html; charset=UTF-8' }
        });
    }

    // =========================================================
    // 逻辑零：首页伪装
    // =========================================================
    if (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/favicon.ico') {
      return new Response(getNginxHtml(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' }
      });
    }

    // =========================================================
    // 逻辑一：Docker Hub 强制鉴权 (防 429)
    // =========================================================
    if (url.pathname === '/token') {
        const tokenUrl = new URL(url.href);
        tokenUrl.hostname = 'auth.docker.io';
        const newHeaders = new Headers(request.headers);
        if (env.USERNAME && env.PASSWORD) {
            const authString = btoa(`${env.USERNAME}:${env.PASSWORD}`);
            newHeaders.set('Authorization', `Basic ${authString}`);
        }
        return fetch(tokenUrl.toString(), {
            method: 'GET',
            headers: newHeaders,
            redirect: 'follow'
        });
    }

    // =========================================================
    // 逻辑二：路由解析与请求转发
    // =========================================================
    const pathParts = url.pathname.split('/');
    let upstream = HUB_HOST;
    let isDockerHub = true;
    let newPath = url.pathname;

    if (pathParts.length > 2) {
        const prefix = pathParts[2];
        if (ROUTES[prefix]) {
            upstream = ROUTES[prefix];
            isDockerHub = false;
            pathParts.splice(2, 1);
            newPath = pathParts.join('/');
        }
    }

    url.hostname = upstream;
    url.pathname = newPath;
    const newRequest = new Request(url, request);
    newRequest.headers.set('Host', upstream);
    const response = await fetch(newRequest);

    // =========================================================
    // 逻辑三：响应头处理
    // =========================================================
    const newHeaders = new Headers(response.headers);
    const wwwAuth = newHeaders.get('Www-Authenticate');
    if (isDockerHub && wwwAuth) {
        const workerHost = url.protocol + '//' + request.headers.get('Host');
        newHeaders.set('Www-Authenticate', wwwAuth.replace(AUTH_URL, workerHost));
    }

    return new Response(response.body, {
        status: response.status,
        headers: newHeaders
    });
  }
};
