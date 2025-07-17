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
        const [headerEncoded] = token.split('.');
        const header = JSON.parse(atob(headerEncoded));
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
        return { verified: true, payload };
    } catch (error) {
        console.error('Token 驗證失敗:', error.message);
        return { verified: false, error: error.message };
    }
}

export const onRequest = async ({ request, env, next }) => {
    const url = new URL(request.url);
    const path = url.pathname;

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

    if (path === '/functions/firebase_jwt_verify/verify-and-set-cookie' && request.method === 'POST') {
        try {
            const { idToken } = await request.json();
            if (!idToken) {
                return new Response(JSON.stringify({ verified: false, message: '缺少 ID Token' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            const { verified, payload, error } = await verifyFirebaseToken(idToken, env);
            if (!verified) {
                return new Response(JSON.stringify({ verified: false, message: error }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            const response = new Response(JSON.stringify({ verified: true, message: '登入成功' }), {
                headers: { 'Content-Type': 'application/json' }
            });

            const expiryDate = new Date(payload.exp * 1000);
            response.headers.set('Set-Cookie', `firebase_jwt=${idToken}; Path=/; Expires=${expiryDate.toUTCString()}; HttpOnly; Secure; SameSite=Lax`);
            return response;

        } catch (e) {
            return new Response(JSON.stringify({ verified: false, message: '伺服器錯誤' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    if (path.startsWith(PROTECTED_PREFIX)) {
        let token;
        const cookieHeader = request.headers.get('Cookie');
        if (cookieHeader) {
            token = cookieHeader.match(/firebase_jwt=([^;]+)/)?.[1];
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
    }

    return next();
};