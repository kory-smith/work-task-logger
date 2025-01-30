const WORK_PROJECT_ID = '2202602227';

// const example = {
// 	event_data: {
// 		can_assign_tasks: false,
// 		child_order: 0,
// 		collapsed: false,
// 		color: 'teal',
// 		created_at: '2025-01-29T23:48:54.935002Z',
// 		default_order: 0,
// 		description: '',
// 		id: '2348004722',
// 		is_archived: true,
// 		is_deleted: false,
// 		is_favorite: false,
// 		is_frozen: false,
// 		name: 'pis piss',
// 		parent_id: null,
// 		shared: false,
// 		sync_id: null,
// 		updated_at: '2025-01-29T23:50:11.296363Z',
// 		v2_id: '6X9JGxPp6XFv3hRr',
// 		v2_parent_id: null,
// 		view_style: 'list',
// 	},
// 	event_name: 'project:archived',
// 	initiator: {
// 		email: 'kor54e@gmail.com',
// 		full_name: 'Kory Smith',
// 		id: '21041386',
// 		image_id: 'b41f5c5c89fc4f9cb02f51165d110303',
// 		is_premium: true,
// 	},
// 	triggered_at: '2025-01-29T23:50:12.392023Z',
// 	user_id: '21041386',
// 	version: '9',
// };

// src/index.js
export default {
	async fetch(request, env) {
		const { DATABASE, TODOIST_CLIENT_SECRET } = env;

		if (request.method !== 'POST') {
			return new Response('Method Not Allowed', { status: 405 });
		}

		try {
			const payload = await request.text();


			const expectedHmac = request.headers.get('x-todoist-hmac-sha256');
			const generatedHmac = await generateTodoistHmac(payload, TODOIST_CLIENT_SECRET);
			if (generatedHmac !== expectedHmac) {
				return new Response('Signature mismatch', { status: 401 });
			}

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

			if (event_data.parent_id === WORK_PROJECT_ID) {
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
			return new Response('Internal Server Error', { status: 500 });
		}
	},
};

async function generateTodoistHmac(payload, todoistSecret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(payload);
	const key = await crypto.subtle.importKey('raw', encoder.encode(todoistSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const hmac = await crypto.subtle.sign('HMAC', key, data);
	return btoa(String.fromCharCode(...new Uint8Array(hmac)));
}

async function assertIsAuthenticTodoistWebhook(request, TODOIST_CLIENT_SECRET) {
	const payload = await request.text();
	const expectedHmac = request.headers.get('x-todoist-hmac-sha256');
	const generatedHmac = await generateTodoistHmac(payload, TODOIST_CLIENT_SECRET);
	if (generatedHmac !== expectedHmac) {
		return new Response('Signature mismatch', { status: 401 });
	}
}
