import { initializeApp, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

// 初始化 Firebase Admin
initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 保護 my-laboratory.pages.dev 的所有路徑
  const idToken = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!idToken) {
    console.error('Missing Authorization header');
    return new Response('Unauthorized: Missing ID Token', { status: 401 });
  }

  try {
    // 驗證 ID Token
    const decodedToken = await getAuth().verifyIdToken(idToken);
    console.log('Verified user:', { uid: decodedToken.uid, email: decodedToken.email });
    // 添加 X-User-ID 頭
    const modifiedRequest = new Request(request, {
      headers: {
        ...Object.fromEntries(request.headers),
        'X-User-ID': decodedToken.uid,
      },
    });
    return await next(modifiedRequest);
  } catch (error) {
    console.error('ID Token verification failed:', error.message);
    return new Response(`Unauthorized: Invalid ID Token - ${error.message}`, { status: 401 });
  }
}