export async function onRequestPost({ request, env }) {
  try {
    // 解析請求中的 JSON 數據
    const { token } = await request.json();

    // 驗證 token 是否有效
    if (!token || typeof token !== 'string' || token.length < 10) {
      return new Response(
        JSON.stringify({ success: false, error: '無效的 Turnstile token' }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff'
          }
        }
      );
    }

    // 從環境變數獲取 Turnstile Secret Key
    const secretKey = env.TURNSTILE_SECRET_KEY;
    if (!secretKey) {
      console.error('Turnstile 密鑰未配置');
      return new Response(
        JSON.stringify({ success: false, error: '伺服器配置錯誤' }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // 向 Turnstile API 發送驗證請求
    const verifyResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: secretKey,
        response: token
      })
    });

    const verification = await verifyResponse.json();

    // 處理驗證結果
    if (verification.success) {
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Content-Type-Options': 'nosniff',
          'Access-Control-Allow-Origin': '*' // 可根據需求限制特定域名
        }
      });
    } else {
      console.log('Turnstile 驗證失敗:', verification['error-codes']);
      return new Response(
        JSON.stringify({
          success: false,
          error: 'Turnstile 驗證失敗'
          // 生產環境中可移除 error-codes
          // codes: verification['error-codes']
        }),
        {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  } catch (err) {
    console.error('伺服器錯誤:', err);
    return new Response(
      JSON.stringify({ success: false, error: '伺服器錯誤' }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}