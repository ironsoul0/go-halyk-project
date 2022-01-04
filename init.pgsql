CREATE TABLE "users" (
  "id" SERIAL PRIMARY KEY NOT NULL,
  "username" varchar NOT NULL UNIQUE,
  "password" varchar NOT NULL,
  "iin" varchar NOT NULL UNIQUE,
  "role" varchar NOT NULL DEFAULT 'user',
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT now()::TIMESTAMPTZ
);

INSERT INTO "users" (username, password, iin, role) VALUES ('admin', 'admin', '0123', 'admin');
INSERT INTO "users" (username, password, iin, role) VALUES ('halyk', 'halyk', '4567', 'user');