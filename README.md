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

### app/api/auth/signup/route.ts
```bash
import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { log } from "@/lib/logger"
import { handlePrismaError } from "@/lib/errors/handlePrismaError";
import { signupSchema } from "@/lib/validations/user.schema";
import { hashPassword } from "@/lib/auth/password";

export async function POST(request: NextRequest) {
    const requestId = crypto.randomUUID();
    try {
        log.info(
            {
                requestId,
                path: request.nextUrl.pathname,
                method: request.method,
            },
            "User data received"
        )

        const jsonBody = await request.json();
        const validation = signupSchema.safeParse(jsonBody);

        if (!validation.success) {
            log.warn(
                {
                    requestId,
                    errors: validation.error.flatten().fieldErrors,
                },
                "Invalid User Input"
            )

            return NextResponse.json(
                {status: "fail", requestId, message: "Invalid user input", errors: validation.error.flatten().fieldErrors},
                {status: 400}
            )
        }

        const {name, email, password} = validation.data;
        const passwordHash = await hashPassword(password);

        const userSignup = await prisma.user.create({
            data: { name, email, passwordHash },
            select: { id: true, name: true, email: true }
        })
        

        
        log.info(
            {
                requestId,
                name: validation.data.name,
                email: validation.data.email,
            },
            "User created successfull!"
        )

        return NextResponse.json(
            {status: "success", requestId, message: "User account created successfull!", data: userSignup},
            {status: 201}
        )
    } catch (error) {
        const { status, message } = handlePrismaError(error);
        log.error(
        { 
            requestId,
            err: error instanceof Error 
                ? { message: error.message, stack: error.stack, name: error.name }
                : String(error),
        },
        message
    )
    return NextResponse.json(
        { status: "fail", requestId, message },
        { status }
    )
    }
}
```
---

### app/api/auth/login/route.ts
```bash
import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { log } from "@/lib/logger"
import { handlePrismaError } from "@/lib/errors/handlePrismaError";
import { loginSchema } from "@/lib/validations/user.schema";
import { verifyPassword } from "@/lib/auth/password";
import { signAccessToken, generateRefreshToken } from "@/lib/auth/tokens";

export async function POST(request: NextRequest) {
    const requestId = crypto.randomUUID();
    try {
        log.info(
            {
                requestId,
                path: request.nextUrl.pathname,
                method: request.method,
            },
            "Login data received"
        )

        const jsonBody = await request.json();
        const validation = loginSchema.safeParse(jsonBody);

        if (!validation.success) {
            log.warn(
                {
                    requestId,
                    errors: validation.error.flatten().fieldErrors,
                },
                "Invalid Input"
            )
            return NextResponse.json(
                {status: "fail", requestId, message: "Invalid Input", errors: validation.error.flatten().fieldErrors},
                {status: 400}
            )
        }

        const { email, password } = validation.data;

        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user || !(await verifyPassword(user.passwordHash, password))) {
            log.warn(
                {
                    requestId,
                    email,
                },
                "Failed login attempt"
            )

            return NextResponse.json(
                {status: "fail", requestId, message: "Invalid email or password"},
                {status: 401}
            )
        }

        const accessToken = await signAccessToken(user.id, user.role);
        const { raw: refreshRaw, hashed: refreshHashed } = generateRefreshToken();

        await prisma.refreshToken.create({
            data: {
                tokenHash: refreshHashed,
                userId: user.id,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            },
        });

        

        const response = NextResponse.json({
            status: "success",
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
            },
        });

       response.cookies.set("access_token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 15, // 15min
       }) 

       response.cookies.set("refresh_token", refreshRaw, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/api/auth", // শুধু auth route এই accessible
        maxAge: 60 * 60 * 24 * 7,
       })

       log.info(
            {
                requestId,
                userId: user.id,
                email: user.email,
            },
            "User logged in"
        )
        
        return response;
        
    } catch (error) {
        const { status, message } = handlePrismaError(error);
        log.error(
        { 
            requestId,
            err: error instanceof Error 
                ? { message: error.message, stack: error.stack, name: error.name }
                : String(error),
        },
        message
    )
    return NextResponse.json(
        { status: "fail", requestId, message },
        { status }
    )
    }
}
```
---

### proxy.ts — access token verify + attach identity
```bash
import { NextRequest, NextResponse } from "next/server";
import { log } from "@/lib/logger";
import { verifyAccessToken } from "@/lib/auth/tokens";

const PROTECTED_PREFIXES = [
    "/api/profile",
    "/api/orders",
]

export async function proxy(request:NextRequest){
    const requestId = crypto.randomUUID();
    
    const isProtected = PROTECTED_PREFIXES.some((p)=> request.nextUrl.pathname.startsWith(p));

    if (!isProtected) return NextResponse.next();

    const token = request.cookies.get("access_token")?.value;

    if (!token) {
        log.warn(
            {
                requestId,
                path: request.nextUrl.pathname,
                method: request.method,
            },
            "Authentication required"
        )
        return NextResponse.json(
            {status: "fail", requestId, message: "Authentication required"},
            {status: 401}
        )
    }

    try {
        
        const payload = await verifyAccessToken(token);
        
        const headers = new Headers(request.headers);
        headers.set("x-user-id", payload.sub as string);
        headers.set("x-user-role", payload.role as string);

        return NextResponse.next(
            { request: { headers } }
        );

    } catch (error) {
        log.error(
            { 
                requestId,
                error,
             },
            "Access token verification failed"
        )

        return NextResponse.json(
            {status: "fail", requestId, message: "Invalid or expired token"},
            {status: 401}
        )
    }

}
```
---

### app/api/auth/refresh/route.ts
```bash
import { NextRequest, NextResponse } from "next/server";
import  prisma  from "@/lib/prisma";
import { signAccessToken, generateRefreshToken, hashRefreshToken } from "@/lib/auth/tokens";
import { log } from "@/lib/logger";

export async function POST(request: NextRequest) {
    const requestId = crypto.randomUUID();

  const rawRefresh = request.cookies.get("refresh_token")?.value;

  if (!rawRefresh) {
    log.warn(
        {
            requestId,
        },
        ""
    )
    return NextResponse.json(
        { status: "fail", requestId, message: "" }, 
        { status: 401 }
    );
  }

  const tokenHash = hashRefreshToken(rawRefresh);

  const stored = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    include: { user: true },
  });

  if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
    log.warn(
        {
            requestId,
        },
        "Session expired"
    )
    return NextResponse.json(
        { status: "fail", message: "Session expired" }, 
        { status: 401 }
    );
  }

  // rotate: revoke old, issue new — prevents replay if token was stolen
  const { raw: newRaw, hashed: newHashed } = generateRefreshToken();

  await prisma.$transaction([
    prisma.refreshToken.update({ 
        where: { id: stored.id }, 
        data: { revokedAt: new Date() }
     }),

    prisma.refreshToken.create({
      data: {
        tokenHash: newHashed,
        userId: stored.userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    }),
  ]);

  const newAccess = await signAccessToken(stored.userId, stored.user.role);

  log.info(
    {
        requestId,
    },
    "success"
  )

  const response = NextResponse.json({ status: "success" });

  response.cookies.set("access_token", newAccess, {
    httpOnly: true, 
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax", 
    path: "/", maxAge: 60 * 15,
  });
  response.cookies.set("refresh_token", newRaw, {
    httpOnly: true, 
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax", 
    path: "/api/auth", 
    maxAge: 60 * 60 * 24 * 7,
  });

  return response;
}
```
---

###
```bash

```
---
