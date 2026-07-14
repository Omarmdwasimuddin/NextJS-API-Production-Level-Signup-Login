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
  isVerified    Boolean  @default(false)
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt

  refreshTokens RefreshToken[]
  emailOtps     EmailOtp[]
}

model EmailOtp {
  id          String   @id @default(cuid())
  userId      String
  user        User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  otpHash     String   // HMAC hashed, raw kokhono store hoy na
  purpose     OtpPurpose @default(SIGNUP_VERIFY)
  attempts    Int      @default(0)   // koto bar wrong try hoyeche
  maxAttempts Int      @default(5)
  expiresAt   DateTime
  consumedAt  DateTime?              // successfully verify hole set hobe
  createdAt   DateTime @default(now())

  @@index([userId, purpose])
}

enum OtpPurpose {
  SIGNUP_VERIFY
  LOGIN_2FA
  PASSWORD_RESET
}

model RefreshToken {
  id         String   @id @default(cuid())
  tokenHash  String   @unique
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

### lib/auth/tokens.ts (Cookie-based JWT authentication)
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

### lib/auth/otp.ts
```bash
import { createHmac, randomInt } from "crypto";
import { env } from "@/lib/validations/env";

const OTP_HMAC_KEY = env.OTP_HMAC_SECRET;
const OTP_LENGTH = 6;
const OTP_EXPIRY_MINUTES = 10;
const OTP_MAX_ATTEMPTS = 5;
const OTP_RESEND_COOLDOWN_SECONDS = 60;

export function generateOtp(): string {
  return randomInt(100000, 1000000).toString();
}

export function hashOtp(otp: string, email: string): string {
  return createHmac("sha256", OTP_HMAC_KEY)
    .update(`${email.toLowerCase()}:${otp}`)
    .digest("hex");
}

export function getOtpExpiry(): Date {
  return new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
}

export { OTP_LENGTH, OTP_EXPIRY_MINUTES, OTP_MAX_ATTEMPTS, OTP_RESEND_COOLDOWN_SECONDS };
```
---

### lib/email/sendEmail.ts
```bash
import { Resend } from "resend";
import { env } from "@/lib/validations/env";
import { log } from "@/lib/logger";

const resend = new Resend(env.RESEND_API_KEY);

export async function sendOtpEmail(to: string, otp: string, name: string) {
  try {
    const { data, error } = await resend.emails.send({
      from: env.EMAIL_FROM,
      to,
      subject: "তোমার Verification Code",
      html: `
        <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
          <h2>Email Verify করো</h2>
          <p>হ্যালো ${name},</p>
          <p>তোমার account verify করার জন্য এই কোডটা ব্যবহার করো:</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 16px; background: #f4f4f4; text-align: center; border-radius: 8px;">
            ${otp}
          </div>
          <p style="color: #666; font-size: 14px;">এই কোডটা ১০ মিনিটের মধ্যে expire হয়ে যাবে। যদি তুমি এই request না করে থাকো, এই email ignore করো।</p>
        </div>
      `,
    });

    if (error) {
      log.error({ error, to }, "Failed to send OTP email");
      throw new Error("Email send failed");
    }

    return data;
  } catch (error) {
    log.error({ error, to }, "Email service error");
    throw error;
  }
}
```
---

### app/api/auth/signup/route.ts
```bash
import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { log } from "@/lib/logger";
import { handlePrismaError } from "@/lib/errors/handlePrismaError";
import { signupSchema } from "@/lib/validations/user.schema";
import { hashPassword } from "@/lib/auth/password";
import { generateOtp, hashOtp, getOtpExpiry } from "@/lib/auth/otp";
import { sendOtpEmail } from "@/lib/email/sendEmail";

export async function POST(request: NextRequest) {
    const requestId = crypto.randomUUID();
    try {
        log.info(
            { requestId, path: request.nextUrl.pathname, method: request.method },
            "User data received"
        )

        const jsonBody = await request.json();
        const validation = signupSchema.safeParse(jsonBody);

        if (!validation.success) {
            log.warn(
                { requestId, errors: validation.error.flatten().fieldErrors },
                "Invalid User Input"
            )
            return NextResponse.json(
                { status: "fail", requestId, message: "Invalid user input", errors: validation.error.flatten().fieldErrors },
                { status: 400 }
            )
        }

        const { name, email, password } = validation.data;
        const passwordHash = await hashPassword(password);

        const otp = generateOtp();
        const otpHash = hashOtp(otp, email);

        const result = await prisma.$transaction(async (tx) => {
            const user = await tx.user.create({
                data: { name, email, passwordHash, isVerified: false },
                select: { id: true, name: true, email: true },
            });

            await tx.emailOtp.create({
                data: {
                    userId: user.id,
                    otpHash,
                    purpose: "SIGNUP_VERIFY",
                    expiresAt: getOtpExpiry(),
                },
            });

            return user;
        });

        try {
            await sendOtpEmail(result.email, otp, result.name);
        } catch (emailError) {
            // Email fail হলেও user creation rollback করবো না —
            // user resend-otp দিয়ে আবার try করতে পারবে
            log.error(
                { requestId, userId: result.id, error: emailError },
                "OTP email failed to send after signup"
            )
        }

        log.info(
            { requestId, name: result.name, email: result.email },
            "User created, OTP sent for verification"
        )

        return NextResponse.json(
            {
                status: "success",
                requestId,
                message: "Account created. Check your email for the verification code.",
                data: { id: result.id, name: result.name, email: result.email },
            },
            { status: 201 }
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

### lib/rate-limit.ts
```bash
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { env } from "./validations/env";


const redis = new Redis({
    url: env.UPSTASH_REDIS_REST_URL,
    token: env.UPSTASH_REDIS_REST_TOKEN,
});

export const ipRateLimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(10, "1 m"),
    analytics: true,
    prefix: "ratelimit:login:ip",
});

export const emailRateLimit = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(5, "1 m"),
    analytics: true,
    prefix: "ratelimit:login:email",
});
```
---

### lib/get-client-ip.ts
```bash
import { NextRequest } from "next/server";

export function getClientIp(request: NextRequest): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim();
  }
  const realIp = request.headers.get("x-real-ip");
  if (realIp) return realIp;
  return "unknown";
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
import { ipRateLimit, emailRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/get-client-ip";

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

        const clientIp = getClientIp(request);
        const ipResult = await ipRateLimit.limit(clientIp);

        if (!ipResult.success) {
            log.warn(
                {
                    requestId,
                    ip: clientIp,
                    remaining: ipResult.remaining,
                    reset: ipResult.reset,
                },
                "IP rate limit exceeded on login"
            )
            return NextResponse.json(
                {
                    status: "fail",
                    requestId,
                    message: "Too many login attempts. Please try again later.",
                },
                {
                    status: 429,
                    headers: {
                        "Retry-After": Math.ceil((ipResult.reset - Date.now()) / 1000).toString(),
                    },
                }
            )
        }

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

        const emailResult = await emailRateLimit.limit(email);

        if (!emailResult.success) {
            log.warn(
                {
                    requestId,
                    email,
                    ip: clientIp,
                    reset: emailResult.reset,
                },
                "Email rate limit exceeded on login"
            )
            return NextResponse.json(
                {
                    status: "fail",
                    requestId,
                    message: "Too many attempts for this account. Please try again later.",
                },
                {
                    status: 429,
                    headers: {
                        "Retry-After": Math.ceil((emailResult.reset - Date.now()) / 1000).toString(),
                    },
                }
            )
        }

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
        maxAge: 60 * 15,
       }) 

       response.cookies.set("refresh_token", refreshRaw, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/api/auth",
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
        "Refresh token cookie is missing"
    )
    return NextResponse.json(
        { status: "fail", requestId, message: "Refresh token is required" }, 
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
            userID: stored?.userId,
        },
        "Invalid, revoked, or expired refresh token"
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
        userID: stored.userId,
    },
    "Refresh token rotated successfully"
  )

  const response = NextResponse.json({ status: "success", requestId, message: "Session refreshed successfully" });

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
