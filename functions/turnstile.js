export async function onRequest() {
  return new Response("Turnstile Test", { status: 200 });
}

export async function onRequestPost({ request, env }) {
  try {
    // 驗證環境變數
    if (!env.TURNSTILE_SECRET_KEY) {
      console.error({
        error: 'Missing configuration',
        detail: 'TURNSTILE_SECRET_KEY not set in environment'
      });
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
    
    // 獲取客戶端 IP
    const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';

    // 驗證 token 格式
    if (!token || typeof token !== 'string' || token.length < 10) {
      console.warn({
        error: 'Invalid token',
        detail: 'Token validation failed',
        clientIp
      });
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

    // 準備 Turnstile API 請求
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
            // 使用環境變數配置允許的域名
            'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
            'Access-Control-Allow-Methods': 'POST',
            'Access-Control-Max-Age': '86400'
          }
        }
      );
    } else {
      console.warn({
        error: 'Turnstile verification failed',
        errorCodes: verification['error-codes'],
        clientIp
      });
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Turnstile verification failed'
        }),
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
  } catch (err) {
    console.error({
      error: 'Server error',
      detail: err.message,
      stack: err.stack
    });
    return new Response(
      JSON.stringify({ success: false, error: 'Internal server error' }),
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
}