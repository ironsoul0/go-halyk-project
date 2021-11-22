CREATE TABLE "users" (
  "id" SERIAL PRIMARY KEY NOT NULL,
  "username" varchar NOT NULL UNIQUE,
  "password" varchar NOT NULL,
  "iin" varchar NOT NULL UNIQUE,
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT now()::TIMESTAMPTZ
);

INSERT INTO "users" (username, password, iin) VALUES ('admin', 'admin', '0123');
INSERT INTO "users" (username, password, iin) VALUES ('halyk', 'halyk', '4567');