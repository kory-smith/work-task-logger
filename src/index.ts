export default {
	async fetch(request, env) {
		const { DATABASE, TODOIST_CLIENT_SECRET } = env;

		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		try {
			const payload = await request.text();

			await assertIsAuthenticTodoistWebhook(request, payload, TODOIST_CLIENT_SECRET);

			const parsedPayload = JSON.parse(payload);
			const { event_name, event_data } = parsedPayload;

			if (!event_name || !event_data) {
				return new Response('Invalid payload', { status: 400 });
			}

			if (event_name === 'item:completed') {
				await DATABASE.prepare(
					`INSERT INTO tasks (id, project_id, content, created_at, completed_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
           content = excluded.content,
           completed_at = excluded.completed_at`
				)
					.bind(event_data.id, event_data.project_id, event_data.content, event_data.added_at, event_data.completed_at)
					.run();
			}

			if (isWorkProject(event_data)) {
				if (event_name === 'project:added' || event_name === 'project:updated' || event_name === 'project:archived') {
					await DATABASE.prepare(
						`INSERT INTO projects (id, name, started_at, completed_at)
						 VALUES (?, ?, ?, ?)
						 ON CONFLICT(id) DO UPDATE
							 SET name = excluded.name,
									 completed_at = CASE
										 WHEN excluded.completed_at IS NOT NULL THEN excluded.completed_at
										 ELSE projects.completed_at
									 END`
					)
						.bind(event_data.id, event_data.name, event_data.created_at, event_name === 'project:archived' ? event_data.updated_at : null)
						.run();
				}
			}

			return new Response('Data processed successfully', { status: 200 });
		} catch (error) {
			console.error('Error processing request:', error);
			if (error.cause === 'signature_mismatch') {
				return new Response('Signature mismatch', { status: 401 });
			} else return new Response('Internal Server Error', { status: 500 });
		}
	},
};

function isWorkProject(event_data) {
	const workColors = ['blue', 'teal', 'sky_blue', 'light_blue'];
	return workColors.some((color) => color === event_data.color);
}

async function generateTodoistHmac(payload, todoistSecret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(payload);
	const key = await crypto.subtle.importKey('raw', encoder.encode(todoistSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const hmac = await crypto.subtle.sign('HMAC', key, data);
	return btoa(String.fromCharCode(...new Uint8Array(hmac)));
}

async function assertIsAuthenticTodoistWebhook(request, payload, TODOIST_CLIENT_SECRET) {
	const expectedHmac = request.headers.get('x-todoist-hmac-sha256');
	const generatedHmac = await generateTodoistHmac(payload, TODOIST_CLIENT_SECRET);
	if (generatedHmac !== expectedHmac) {
		throw Error('Signature mismatch', { cause: 'signature_mismatch' });
	}
}
