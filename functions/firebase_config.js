export async function onRequestGet(context) {

    const config = {
        apiKey: context.env.FIREBASE_API_KEY, 
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