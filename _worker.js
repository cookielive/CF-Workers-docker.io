// _worker.js - 终极完整版
// 1. Docker Hub 强制鉴权 (解决 429)
// 2. 多路镜像仓库支持 (支持 gcr, quay 等)
// 3. 首页伪装成 Nginx (浏览器访问隐藏身份)

const HUB_HOST = 'registry-1.docker.io';
const AUTH_URL = 'https://auth.docker.io';

// 路由定义：前缀 -> 目标仓库
const ROUTES = {
    // 生产环境常用
    "quay": "quay.io",
    "gcr": "gcr.io",
    "k8s-gcr": "k8s.gcr.io",
    "k8s": "registry.k8s.io",
    "ghcr": "ghcr.io",
    "cloudsmith": "docker.cloudsmith.io",
    "nvcr": "nvcr.io",
    
    // 兼容原有配置
    "test": "registry-1.docker.io",
};

// Nginx 伪装页面模板
function getNginxHtml() {
    return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // =========================================================
    // 逻辑零：首页伪装 (浏览器访问时显示 Nginx 页面)
    // =========================================================
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return new Response(getNginxHtml(), {
        status: 200,
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
            'Cache-Control': 'no-store' // 不缓存，防止影响后续调试
        }
      });
    }

    // =========================================================
    // 逻辑一：处理 Docker Hub 的 Token 请求 (这是防 429 的关键)
    // =========================================================
    // 只有当客户端请求的是原本属于 Docker Hub 的 Token 时，我们才拦截并注入账号
    if (url.pathname === '/token') {
        const tokenUrl = new URL(url.href);
        tokenUrl.hostname = 'auth.docker.io';

        const newHeaders = new Headers(request.headers);
        
        // 核心：注入你的 Docker Hub 凭证
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
    
    // 解析路径，判断是否包含路由前缀 (例如 /v2/gcr/...)
    const pathParts = url.pathname.split('/');
    let upstream = HUB_HOST; // 默认指向 Docker Hub
    let isDockerHub = true;
    let newPath = url.pathname;

    // 检查是否命中路由前缀
    // pathParts[0] 是空字符串, pathParts[1] 是 v2
    if (pathParts.length > 2) {
        const prefix = pathParts[2];
        if (ROUTES[prefix]) {
            upstream = ROUTES[prefix];
            isDockerHub = false;
            // 移除路由前缀，还原真实路径
            // 例如 /v2/gcr/project/image -> /v2/project/image
            pathParts.splice(2, 1);
            newPath = pathParts.join('/');
        }
    }

    // 构造转发请求
    url.hostname = upstream;
    url.pathname = newPath;

    const newRequest = new Request(url, request);
    newRequest.headers.set('Host', upstream);

    // 发起转发
    const response = await fetch(newRequest);

    // =========================================================
    // 逻辑三：响应头处理 (Www-Authenticate 重写)
    // =========================================================
    
    const newHeaders = new Headers(response.headers);
    const wwwAuth = newHeaders.get('Www-Authenticate');

    // 只有针对 Docker Hub，我们需要把认证地址改回 Worker 自身
    if (isDockerHub && wwwAuth) {
        const workerHost = url.protocol + '//' + request.headers.get('Host');
        // 将 Docker 官方的认证地址替换为 Worker 地址
        newHeaders.set('Www-Authenticate', wwwAuth.replace(AUTH_URL, workerHost));
    }

    return new Response(response.body, {
        status: response.status,
        headers: newHeaders
    });
  }
};
