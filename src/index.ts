interface Env {
  DB: D1Database;
  ASSETS: R2Bucket;
  ENVIRONMENT: string;
}

const json = (data: unknown, init: ResponseInit = {}) =>
  Response.json(data, {
    ...init,
    headers: { 'content-type': 'application/json; charset=utf-8', ...(init.headers ?? {}) },
  });

const notFound = () => json({ error: 'Not found' }, { status: 404 });

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'GET' && pathname === '/api/health') {
      return json({ ok: true, service: 'grand-horizon-hotels', environment: env.ENVIRONMENT });
    }

    if (request.method === 'GET' && pathname === '/api/members') {
      const { results } = await env.DB.prepare(
        'SELECT id, email, first_name, last_name, membership_tier, created_at FROM members ORDER BY created_at DESC LIMIT 100',
      ).all();
      return json({ members: results });
    }

    if (request.method === 'POST' && pathname === '/api/members') {
      const body = (await request.json()) as Partial<Record<string, string>>;
      if (!body.email || !body.firstName || !body.lastName) {
        return json({ error: 'email, firstName, and lastName are required' }, { status: 400 });
      }

      const id = crypto.randomUUID();
      try {
        await env.DB.prepare(
          'INSERT INTO members (id, email, first_name, last_name, membership_tier) VALUES (?, ?, ?, ?, ?)',
        ).bind(id, body.email, body.firstName, body.lastName, body.membershipTier ?? 'standard').run();
      } catch (error) {
        if (String(error).toLowerCase().includes('unique')) {
          return json({ error: 'A member with this email already exists' }, { status: 409 });
        }
        throw error;
      }
      return json({ id, email: body.email }, { status: 201 });
    }

    if (request.method === 'GET' && pathname.startsWith('/api/bookings/')) {
      const memberId = pathname.split('/').pop();
      if (!memberId) return notFound();
      const { results } = await env.DB.prepare(
        'SELECT id, property_name, room_type, check_in, check_out, status, created_at FROM bookings WHERE member_id = ? ORDER BY check_in DESC',
      ).bind(memberId).all();
      return json({ bookings: results });
    }

    if (request.method === 'GET' && pathname.startsWith('/assets/')) {
      const object = await env.ASSETS.get(pathname.slice('/assets/'.length));
      if (!object) return notFound();
      return new Response(object.body, {
        headers: { 'content-type': object.httpMetadata?.contentType ?? 'application/octet-stream', 'cache-control': 'public, max-age=3600' },
      });
    }

    return json({ error: 'Route not found' }, { status: 404 });
  },
};
