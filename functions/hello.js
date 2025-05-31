export async function onRequest(context) {
  return new Response("Hello from turnstile.js", { status: 200 });
}