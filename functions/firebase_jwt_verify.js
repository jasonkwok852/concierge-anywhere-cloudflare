import { jwtVerify, importX509 } from 'jose';

const JWKS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const LOGIN_PAGE = 'https://concierge-anywhere.com/control_center/user_login';
const PROTECTED_PREFIX = '/control_center/private_room';

let cachedKeys = null;
let cachedAt = 0;
const CACHE_TTL = 3600000;

async function getPublicKeys() {
    const now = Date.now();
    if (cachedKeys && now - cachedAt < CACHE_TTL) {
        console.log('使用緩存的公鑰');
        return cachedKeys;
    }
    console.log('獲取新的公鑰');
    const res = await fetch(JWKS_URL);
    if (!res.ok) {
        throw new Error('獲取 Firebase 公鑰失敗');
    }
    cachedKeys = await res.json();
    cachedAt = now;
    return cachedKeys;
}

function base64UrlDecode(str) {
    let output = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (output.length % 4) {
        case 0: break;
        case 2: output += '=='; break;
        case 3: output += '='; break;
        default: throw new Error('不合法的 base64 字符串');
    }
    const decoded = atob(output);
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {
        bytes[i] = decoded.charCodeAt(i);
    }
    return bytes;
}

async function verifyFirebaseToken(token, env) {
    try {
        console.log('開始驗證 Token');
        if (!token) {
            throw new Error('缺少 ID Token');
        }

        const tokenParts = token.split('.');
        if (tokenParts.length !== 3) {
            throw new Error('無效的 Token 格式');
        }

        const [headerEncoded] = tokenParts;
        const headerBytes = base64UrlDecode(headerEncoded);
        const headerText = new TextDecoder().decode(headerBytes);
        const header = JSON.parse(headerText);
        const kid = header.kid;
        
        if (!kid) {
            throw new Error('Token 標頭缺少 key ID');
        }

        const keys = await getPublicKeys();
        const pubKeyPEM = keys[kid];
        
        if (!pubKeyPEM) {
            throw new Error('找不到對應的公鑰');
        }

        const pubKey = await importX509(pubKeyPEM, 'RS256');
        const { payload } = await jwtVerify(token, pubKey, {
            issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`,
            audience: env.FIREBASE_PROJECT_ID,
        });

        const currentTime = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < currentTime) {
            throw new Error('Token 已過期');
        }

        console.log('Token 驗證成功');
        return { 
            verified: true, 
            payload,
            redirect_url: `${PROTECTED_PREFIX}` // 改為只返回 private_room 路徑
        };
    } catch (error) {
        console.error('Token 驗證失敗:', error.message);
        return { 
            verified: false, 
            error: error.message,
            stack: error.stack
        };
    }
}

export const onRequest = async ({ request, env, next }) => {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
        console.log('處理預檢請求');
        return new Response(null, {
            status: 204,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Max-Age': '86400',
            }
        });
    }

    if (path === '/firebase_jwt_verify' && request.method === 'POST') {
        console.log('處理 JWT 驗證請求');
        try {
            const contentType = request.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                return new Response(JSON.stringify({ 
                    verified: false, 
                    message: '請使用 application/json 內容類型' 
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            const requestBody = await request.json();
            const idToken = requestBody.idToken;
            
            if (!idToken) {
                return new Response(JSON.stringify({ 
                    verified: false, 
                    message: '缺少 ID Token' 
                }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            const { verified, payload, error, redirect_url } = await verifyFirebaseToken(idToken, env);
            
            if (!verified) {
                return new Response(JSON.stringify({ 
                    verified: false, 
                    message: error || 'Token 驗證失敗'
                }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            console.log('JWT 驗證成功，設置 cookie');
            return new Response(JSON.stringify({ 
                verified: true, 
                message: '驗證成功',
                redirect_url: redirect_url
            }), {
                status: 200,
                headers: { 
                    'Content-Type': 'application/json',
                    'Set-Cookie': `firebase_jwt=${idToken}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax`
                }
            });

        } catch (e) {
            console.error('伺服器錯誤:', e);
            return new Response(JSON.stringify({ 
                verified: false, 
                message: '伺服器內部錯誤',
                error: e.message,
                stack: e.stack
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    if (path.startsWith(PROTECTED_PREFIX)) {
        console.log('處理受保護路由:', path);
        try {
            let token;
            const authHeader = request.headers.get('Authorization');
            
            if (authHeader && authHeader.startsWith('Bearer ')) {
                token = authHeader.split(' ')[1];
                console.log('從 Authorization 標頭獲取 token');
            } else {
                const cookieHeader = request.headers.get('Cookie');
                if (cookieHeader) {
                    const match = cookieHeader.match(/firebase_jwt=([^;]+)/);
                    token = match ? match[1] : null;
                    console.log('從 Cookie 獲取 token:', token ? '成功' : '失敗');
                }
            }

            if (!token) {
                console.log('未找到 token，重定向到登入頁面');
                return Response.redirect(LOGIN_PAGE, 302);
            }

            const { verified, error } = await verifyFirebaseToken(token, env);
            
            if (!verified) {
                console.log('Token 驗證失敗，重定向到登入頁面');
                const response = Response.redirect(LOGIN_PAGE, 302);
                response.headers.set('Set-Cookie', 'firebase_jwt=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax');
                return response;
            }

            console.log('Token 驗證成功，繼續處理請求');
            return next();
        } catch (e) {
            console.error('保護路由錯誤:', e);
            return new Response(JSON.stringify({ 
                message: '伺服器內部錯誤',
                error: e.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    return next();
};