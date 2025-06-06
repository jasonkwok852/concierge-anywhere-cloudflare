export async function onRequestPost({ request, env }) {
  try {
    // 驗證環境變數
    if (!env.TURNSTILE_SECRET_KEY) {
      console.error('Missing TURNSTILE_SECRET_KEY');
      return new Response(
        JSON.stringify({ success: false, error: 'Server configuration error' }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'",
            'Cache-Control': 'no-store'
          }
        }
      );
    }

    // 解析請求數據
    const { token } = await request.json();
    
    // 驗證 token 格式
    if (!token || typeof token !== 'string' || token.length < 10) {
      console.warn('Invalid token received:', token);
      return new Response(
        JSON.stringify({ success: false, error: 'Invalid Turnstile token' }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'",
            'Cache-Control': 'no-store'
          }
        }
      );
    }

    // 獲取客戶端 IP
    const clientIp = request.headers.get('CF-Connecting-IP') || 
                     (request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || '');

    // 動態設置 CORS Origin
    const origin = request.headers.get('Origin');
    const allowedOrigins = [
      'https://concierge-anywhere.com',
      'https://www.concierge-anywhere.com'
    ];
    const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

    // Turnstile API 請求
    const verifyResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: clientIp
      })
    });

    const verification = await verifyResponse.json();

    // 處理驗證結果
    if (verification.success) {
      return new Response(
        JSON.stringify({ success: true, challenge_ts: verification.challenge_ts }),
        {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'",
            'Cache-Control': 'no-store',
            'Access-Control-Allow-Origin': corsOrigin,
            'Access-Control-Allow-Methods': 'POST',
            'Access-Control-Max-Age': '86400'
          }
        }
      );
    } else {
      console.warn('Turnstile verification failed:', verification['error-codes']);
      let errorMessage = 'Turnstile verification failed';
      if (verification['error-codes']?.length) {
        const errorCode = verification['error-codes'][0];
        errorMessage = errorCode === 'invalid-input-secret' ? 'Invalid server configuration' :
                       errorCode === 'timeout-or-duplicate' ? 'Token expired or already used' :
                       `Verification failed: ${errorCode}`;
      }
      return new Response(
        JSON.stringify({
          success: false,
          error: errorMessage,
          errorCodes: verification['error-codes']
        }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'",
            'Cache-Control': 'no-store',
            'Access-Control-Allow-Origin': corsOrigin
          }
        }
      );
    }
  } catch (err) {
    console.error('Internal server error:', err);
    return new Response(
      JSON.stringify({ success: false, error: 'Internal server error' }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'none'",
          'Cache-Control': 'no-store',
          'Access-Control-Allow-Origin': 'https://concierge-anywhere.com'
        }
      }
    );
  }
}