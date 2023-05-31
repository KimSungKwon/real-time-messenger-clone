import { PrismaClient } from "@prisma/client";

const client = globalThis.prisma || new PrismaClient();

declare global {
  var prisma: PrismaClient | undefined;
}

if (process.env.NODE_ENV !== 'production') {
  globalThis.prisma = client;
}

export default client;