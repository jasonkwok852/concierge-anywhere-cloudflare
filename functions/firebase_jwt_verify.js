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
        return cachedKeys;
    }
    const res = await fetch(JWKS_URL);
    if (!res.ok) {
        throw new Error('獲取 Firebase 公鑰失敗');
    }
    cachedKeys = await res.json();
    cachedAt = now;
    return cachedKeys;
}

async function verifyFirebaseToken(token, env) {
    try {
        // 檢查 token 是否存在
        if (!token) {
            throw new Error('缺少 ID Token');
        }

        // 分割 token 並檢查格式
        const tokenParts = token.split('.');
        if (tokenParts.length !== 3) {
            throw new Error('無效的 Token 格式');
        }

        const [headerEncoded] = tokenParts;
        const header = JSON.parse(Buffer.from(headerEncoded, 'base64').toString());
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

        // 檢查 token 是否過期
        const currentTime = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < currentTime) {
            throw new Error('Token 已過期');
        }

        return { 
            verified: true, 
            payload,
            redirect_url: `${PROTECTED_PREFIX}/my_laboratory` // 添加重定向URL
        };
    } catch (error) {
        console.error('Token 驗證失敗:', error.message);
        return { 
            verified: false, 
            error: error.message,
            stack: error.stack // 添加錯誤堆棧用於調試
        };
    }
}

export const onRequest = async ({ request, env, next }) => {
    const url = new URL(request.url);
    const path = url.pathname;

    // 處理預檢請求
    if (request.method === 'OPTIONS') {
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

    // 處理 JWT 驗證請求
    if (path === '/firebase_jwt_verify' && request.method === 'POST') {
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

    // 處理受保護路由
    if (path.startsWith(PROTECTED_PREFIX)) {
        try {
            let token;
            const authHeader = request.headers.get('Authorization');
            
            // 檢查 Authorization 標頭
            if (authHeader && authHeader.startsWith('Bearer ')) {
                token = authHeader.split(' ')[1];
            } else {
                // 檢查 cookie
                const cookieHeader = request.headers.get('Cookie');
                if (cookieHeader) {
                    const match = cookieHeader.match(/firebase_jwt=([^;]+)/);
                    token = match ? match[1] : null;
                }
            }

            if (!token) {
                return Response.redirect(LOGIN_PAGE, 302);
            }

            const { verified, error } = await verifyFirebaseToken(token, env);
            
            if (!verified) {
                const response = Response.redirect(LOGIN_PAGE, 302);
                response.headers.set('Set-Cookie', 'firebase_jwt=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax');
                return response;
            }

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