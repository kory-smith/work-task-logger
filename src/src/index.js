const WORK_PROJECT_ID = "2202602227";

// src/index.js
export default {
  async fetch(request, env) {
    const { DATABASE, TODOIST_CLIENT_SECRET } = env;

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    try {
      const payload = await request.text();

      const expectedHmac = request.headers.get("x-todoist-hmac-sha256");
      const generatedHmac = await generateTodoistHmac(
        payload,
        TODOIST_CLIENT_SECRET
      );
      if (generatedHmac !== expectedHmac) {
        return new Response("Signature mismatch", { status: 401 });
      }

      const parsedPayload = JSON.parse(payload);
      const { event_name, event_data } = parsedPayload;

      console.log("For kory debugging");
      console.log({ event_name, event_data });
      if (!event_name || !event_data) {
        return new Response("Invalid payload", { status: 400 });
      }

      const currentTimestamp = new Date()
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");

      if (event_name === "item:completed") {
        await DATABASE.prepare(
          `INSERT INTO tasks (id, project_id, content, created_at, completed_at) 
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET 
           content = excluded.content, 
           completed_at = excluded.completed_at`
        )
          .bind(
            event_data.id,
            event_data.project_id,
            event_data.content,
            event_data.added_at,
            event_data.completed_at
          )
          .run();
      }

      if (event_data.parent_id === WORK_PROJECT_ID) {
        if (
          event_name === "project:added" ||
          event_name === "project:archived" ||
          event_name === "project:updated"
        ) {
          await DATABASE.prepare(
            `INSERT INTO projects (id, name, started_at, completed_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET 
             name = excluded.name, 
             completed_at = excluded.completed_at`
          )
            .bind(
              event_data.id,
              event_data.name,
              event_data.created_at,
              event_name === "project:archived" ? event_data.completed_at : null
            )
            .run();
        }
      }

      return new Response("Data processed successfully", { status: 200 });
    } catch (error) {
      console.error("Error processing request:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  },
};

async function generateTodoistHmac(payload, todoistSecret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(todoistSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const hmac = await crypto.subtle.sign("HMAC", key, data);
  return btoa(String.fromCharCode(...new Uint8Array(hmac)));
}
