import bcrypt from "bcrypt";
import NextAuth, { AuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GithubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import { PrismaAdapter } from "@next-auth/prisma-adapter";

import prisma from '@/app/libs/prismadb';

export const authOptions: AuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    GithubProvider({
      clientId: process.env.GITHUB_ID as string,
      clientSecret: process.env.GITHUB_SECRET as string,
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    }),
    CredentialsProvider({
      name: 'credentials', 
      credentials: {
        email: { label: 'email', type: 'text' },
        password: { label: 'password', type: 'password' },
      },
      async authorize(credentials) { // credentials: 유저가 로그인창에서 입력한 값들
        if (!credentials?.email || !credentials?.password) {
          throw new Error('Invalid Credentials');
        }
        // 이메일로 유저 찾고
        const user = await prisma.user.findUnique({
          where: {
            email: credentials.email
          }
        });
        
        if (!user || !user?.hashedPassword) {
          throw new Error('Invalid Credentials');
        }
        // 이메일로 찾은 유저의 비밀번호와 로그인창에서 입력한 비밀번호 비교
        const isCorrectPassword = await bcrypt.compare(
          credentials.password,
          user.hashedPassword
        )

        if (!isCorrectPassword) {
          throw new Error('Invalid Credentials');
        }

        return user;  // 정보가 맞으면
      }
    })
  ],
  debug: process.env.NODE_ENV === 'development',
  session: {
    strategy: "jwt"
  },
  secret: process.env.NEXTAUTH_SECRET,
};

// app 폴더 안에서 route.ts 정의하려면 이거 해야함 (or pages/api/auth)
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };