export async function onRequestGet(context) {
    // 從環境變數中檢索 Firebase 設定詳細資訊。
    // 請確保在您的 Cloudflare Pages 環境設定中設定了 FIREBASE_API_KEY。
    const config = {
        apiKey: context.env.FIREBASE_API_KEY, // 動態獲取的 API 金鑰
        authDomain: "cloudflare-concierge-anywhere.firebaseapp.com",
        projectId: "cloudflare-concierge-anywhere",
        storageBucket: "cloudflare-concierge-anywhere.appspot.com",
        messagingSenderId: "2628861039",
        appId: "1:2628861039:web:bf1873052440751d25219a",
        measurementId: "G-1NDH2C02FF"
    };

    // 以 JSON 格式回傳設定。
    // 'Access-Control-Allow-Origin': '*' 對於 CORS 至關重要，它允許您的前端頁面
    // 獲取此配置，特別是當它們來自不同來源時。
    return new Response(JSON.stringify(config), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*' // 允許來自任何來源的請求
        }
    });
}