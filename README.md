## Next.js API: Production-Level Signup & Login

### prisma/schema.prisma
```bash
generator client {
  provider = "prisma-client-js"
  output   = "../src/generated/prisma"
}

datasource db {
  provider = "postgresql"
}

model User {
  id            String   @id @default(cuid())
  name          String
  email         String   @unique
  passwordHash  String
  role          Role     @default(USER)
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt

  refreshTokens RefreshToken[]
}

model RefreshToken {
  id         String   @id @default(cuid())
  tokenHash  String   @unique   // HMAC hashed, never store raw
  userId     String
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  expiresAt  DateTime
  createdAt  DateTime @default(now())
  revokedAt  DateTime?

  @@index([userId])
}

enum Role {
  USER
  ADMIN
}
```
---

### lib/logger.ts
```bash
import pino from "pino";

export const log = pino({
    level: process.env.LOG_LEVEL || "info",
    timestamp: pino.stdTimeFunctions.isoTime,

    transport:
        process.env.NODE_ENV === "development"
            ? {
                  target: "pino-pretty",
                  options: {
                      colorize: true,
                      translateTime: "SYS:standard",
                  },
              }
            : undefined,
});
```
---

### lib/errors/handlePrismaError.ts
```bash
import { Prisma } from "@/generated/prisma";


export function handlePrismaError(error: unknown) {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    switch (error.code) {
      case "P2002": return { status: 409, message: "Duplicate entry" };
      case "P2003": return { status: 400, message: "Invalid reference" };
      case "P2025": return { status: 404, message: "Not found" };
      default: return { status: 500, message: "Database error" };
    }
  }
  return { status: 500, message: "Internal server error" };
}
```
---

###  lib/validations/user.schema.ts
```bash
import { z } from "zod";


export const signupSchema = z.object({

    name: z.string().trim().min(2).max(50),
    email: z.string().trim().toLowerCase().email(),

    password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Must contain an uppercase letter")
    .regex(/[a-z]/, "Must contain a lowercase letter")
    .regex(/[0-9]/, "Must contain a number")
    .regex(/[^A-Za-z0-9]/, "Must contain a special character"),

});

export const loginSchema = z.object({

    email: z.string().trim().toLowerCase().email(),
    password: z.string().min(1),

})

export type SignupUserInput = z.infer<typeof signupSchema>;
export type LoginUserInput = z.infer<typeof loginSchema>;
```
---

### lib/validations/env.ts
```bash
import { z } from "zod";


export const envSchema = z.object({

    DATABASE_URL: z.string().url(),
    DIRECT_URL: z.string().url(),
    JWT_ACCESS_SECRET: z.string().min(32),
    REFRESH_HMAC_SECRET: z.string().min(32),
    APP_URL:z.string().url(),
    NODE_ENV: z.enum([ "development", "production", "test" ])

});

export const env = envSchema.parse(process.env);
```
---

### lib/auth/password.ts
```bash
import { hash, verify } from "@node-rs/argon2";

const ARGON2_OPTIONS = {
  algorithm: 2,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
};

export async function hashPassword(password: string) {
  return hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(
  hashValue: string,
  password: string
) {
  return verify(hashValue, password);
}
```
---

### lib/auth/tokens.ts
```bash
import { SignJWT, jwtVerify } from "jose";
import { createHmac, randomBytes, randomUUID } from "crypto";
import { env } from "@/lib/validations/env";

const ACCESS_KEY = new TextEncoder().encode(env.JWT_ACCESS_SECRET);
const REFRESH_HMAC_KEY = env.REFRESH_HMAC_SECRET!;

export async function signAccessToken(userId: string, role: string) {
  return new SignJWT({ role })
    .setSubject(userId)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setIssuer(env.APP_URL)
    .setAudience("easy-shop")
    .setExpirationTime("15m")
    .setJti(randomUUID())
    .sign(ACCESS_KEY);
}

export async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, ACCESS_KEY, {
    issuer: env.APP_URL,
    audience: "easy-shop",
  });
  return payload; // { sub: userId, role }
}

// Refresh token: opaque random string, not JWT — safer, easy to revoke via DB
export function generateRefreshToken() {
  const raw = randomBytes(48).toString("hex");
  const hashed = createHmac("sha256", REFRESH_HMAC_KEY).update(raw).digest("hex");
  return { raw, hashed };
}

export function hashRefreshToken(raw: string) {
  return createHmac("sha256", REFRESH_HMAC_KEY).update(raw).digest("hex");
}
```
---

###
```bash

```
---

###
```bash

```
---

###
```bash

```
---
