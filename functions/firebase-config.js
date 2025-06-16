export async function onRequest(context) {
  const firebaseConfig = {
    apiKey: context.env.FIREBASE_WEB_API_KEY,
    authDomain: "concierge-anywhere.com",
    projectId: "Cloudflare-Concierge-Anywhere"
  };
  return new Response(JSON.stringify(firebaseConfig), {
    headers: { 'Content-Type': 'application/json' }
  });
}