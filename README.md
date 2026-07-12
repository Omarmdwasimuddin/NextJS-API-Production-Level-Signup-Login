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

###
```bash

```
---

###
```bash

```
---
