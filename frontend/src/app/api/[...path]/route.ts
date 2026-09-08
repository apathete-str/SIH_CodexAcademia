import { NextRequest } from 'next/server';

const configuredBackendUrl = process.env.API_PROXY_URL || process.env.NEXT_PUBLIC_API_URL || '';
const backendUrl = configuredBackendUrl && /^https?:\/\//.test(configuredBackendUrl)
  ? configuredBackendUrl
  : configuredBackendUrl
    ? `https://${configuredBackendUrl}`
    : '';

async function forward(request: NextRequest, path: string[]) {
  if (!backendUrl) {
    return Response.json({ detail: 'API_PROXY_URL is not configured.' }, { status: 503 });
  }

  const target = `${backendUrl.replace(/\/$/, '')}/${path.join('/')}${request.nextUrl.search}`;
  const headers = new Headers(request.headers);
  headers.delete('host');

  const response = await fetch(target, {
    method: request.method,
    headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer(),
  });

  return new Response(response.body, {
    status: response.status,
    headers: response.headers,
  });
}

export async function GET(request: NextRequest, context: { params: { path: string[] } }) {
  return forward(request, context.params.path);
}

export async function POST(request: NextRequest, context: { params: { path: string[] } }) {
  return forward(request, context.params.path);
}