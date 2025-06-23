// 檔案: /functions/firebase-config.js
export async function onRequestGet(context) {
    // 從環境變量獲取配置
    const config = {
        apiKey: "AIzaSyBtEeUPR3Nzvkx4N-nWxUm-x2oHhtxP14Y",
        authDomain: "cloudflare-concierge-anywhere.firebaseapp.com",
        projectId: "cloudflare-concierge-anywhere",
        storageBucket: "cloudflare-concierge-anywhere.appspot.com",
        messagingSenderId: "2628861039",
        appId: "1:2628861039:web:bf1873052440751d25219a",
        measurementId: "G-1NDH2C02FF"
    };

    return new Response(JSON.stringify(config), {
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}