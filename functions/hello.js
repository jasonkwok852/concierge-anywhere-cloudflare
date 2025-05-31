export async function onRequest() {
  return new Response("Hello World", { status: 200 });
}