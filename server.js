import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { cors } from "hono/cors";
import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = new Hono();
app.use("*", cors());

// "Base de datos" en memoria por ahora
let users = [];
let todos = [];

// SECRET para JWT (luego lo pasamos a variable de entorno en Railway)
const SECRET = "super-secret-key-eva3";

// ----------------------------
// Helpers
// ----------------------------
function generateToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
    },
    SECRET,
    { expiresIn: "7d" }
  );
}

function auth(c) {
  try {
    const header = c.req.header("Authorization");
    if (!header) return null;

    const token = header.replace("Bearer ", "").trim();
    const decoded = jwt.verify(token, SECRET);
    return decoded;
  } catch (e) {
    return null;
  }
}

// ----------------------------
// HEALTH
// ----------------------------
app.get("/health", (c) => {
  return c.json({
    status: "ok",
    timestamp: new Date().toISOString(),
  });
});

// ----------------------------
// AUTH REGISTER
// ----------------------------
app.post("/auth/register", async (c) => {
  const body = await c.req.json().catch(() => null);

  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
  });

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      {
        success: false,
        error: "Datos inválidos",
        details: parsed.error.flatten(),
      },
      400
    );
  }

  const { email, password } = parsed.data;

  const exists = users.find((u) => u.email === email);
  if (exists) {
    return c.json(
      {
        success: false,
        error: "User already exists",
      },
      400
    );
  }

  // IMPORTANTE: para no matar CPUs como el profe,
  // usamos un costo moderado
  const hashed = await bcrypt.hash(password, 8);

  const user = {
    id: String(users.length + 1),
    email,
    password: hashed,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  users.push(user);

  const token = generateToken(user);

  return c.json(
    {
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
        token,
      },
    },
    201
  );
});

// ----------------------------
// AUTH LOGIN
// ----------------------------
app.post("/auth/login", async (c) => {
  const body = await c.req.json().catch(() => null);

  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(6),
  });

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      {
        success: false,
        error: "Datos inválidos",
      },
      400
    );
  }

  const { email, password } = parsed.data;

  const user = users.find((u) => u.email === email);
  if (!user) {
    return c.json(
      { success: false, error: "Invalid credentials" },
      401
    );
  }

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    return c.json(
      { success: false, error: "Invalid credentials" },
      401
    );
  }

  const token = generateToken(user);

  return c.json({
    success: true,
    data: {
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
      token,
    },
  });
});

// ----------------------------
// GET TODOS (del usuario autenticado)
// ----------------------------
app.get("/todos", (c) => {
  const decoded = auth(c);
  if (!decoded) {
    return c.json(
      { success: false, error: "Missing or invalid authorization header" },
      401
    );
  }

  const userTodos = todos.filter((t) => t.userId === decoded.sub);

  return c.json({
    success: true,
    data: userTodos,
    count: userTodos.length,
  });
});

// ----------------------------
// CREATE TODO
// ----------------------------
app.post("/todos", async (c) => {
  const decoded = auth(c);
  if (!decoded) {
    return c.json(
      { success: false, error: "Missing or invalid authorization header" },
      401
    );
  }

  const body = await c.req.json().catch(() => null);

  const schema = z.object({
    title: z.string().min(1),
    completed: z.boolean().optional(),
    location: z
      .object({
        latitude: z.number(),
        longitude: z.number(),
      })
      .optional(),
    photoUri: z.string().optional(),
  });

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      { success: false, error: "Datos inválidos" },
      400
    );
  }

  const { title, completed = false, location, photoUri } = parsed.data;

  const now = new Date().toISOString();

  const todo = {
    id: String(todos.length + 1),
    userId: decoded.sub,
    title,
    completed,
    location: location ?? null,
    photoUri: photoUri ?? null,
    createdAt: now,
    updatedAt: now,
  };

  todos.push(todo);

  return c.json(
    {
      success: true,
      data: todo,
    },
    201
  );
});

// ----------------------------
// UPDATE TODO (PATCH parcial)
// ----------------------------
app.patch("/todos/:id", async (c) => {
  const decoded = auth(c);
  if (!decoded) {
    return c.json(
      { success: false, error: "Missing or invalid authorization header" },
      401
    );
  }

  const id = c.req.param("id");
  const body = await c.req.json().catch(() => ({}));

  const todo = todos.find(
    (t) => t.id === id && t.userId === decoded.sub
  );
  if (!todo) {
    return c.json(
      { success: false, error: "Todo not found" },
      404
    );
  }

  if (typeof body.title === "string") {
    todo.title = body.title;
  }
  if (typeof body.completed === "boolean") {
    todo.completed = body.completed;
  }
  if (body.location && typeof body.location === "object") {
    todo.location = body.location;
  }
  if (typeof body.photoUri === "string") {
    todo.photoUri = body.photoUri;
  }

  todo.updatedAt = new Date().toISOString();

  return c.json({
    success: true,
    data: todo,
  });
});

// ----------------------------
// DELETE TODO
// ----------------------------
app.delete("/todos/:id", (c) => {
  const decoded = auth(c);
  if (!decoded) {
    return c.json(
      { success: false, error: "Missing or invalid authorization header" },
      401
    );
  }

  const id = c.req.param("id");

  const index = todos.findIndex(
    (t) => t.id === id && t.userId === decoded.sub
  );
  if (index === -1) {
    return c.json(
      { success: false, error: "Todo not found" },
      404
    );
  }

  const [deleted] = todos.splice(index, 1);

  return c.json({
    success: true,
    data: deleted,
    message: "Todo deleted",
  });
});

// ----------------------------
// START SERVER
// ----------------------------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

serve(
  {
    fetch: app.fetch,
    port: PORT,
  },
  () => {
    console.log(`API running on http://localhost:${PORT}`);
  }
);
