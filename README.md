## Next.js API: Production-Level Signup & Login

#### prisma/schema.prisma
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
