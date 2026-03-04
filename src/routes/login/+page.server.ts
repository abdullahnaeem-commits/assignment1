import { db } from "$lib/db";
import { users, sessions } from "$lib/schema";
import { eq } from "drizzle-orm";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { fail, redirect } from "@sveltejs/kit";
import type { Actions } from "./$types";

export const actions: Actions = {
  default: async ({ request, cookies }) => {
    const form = await request.formData();
    const email = form.get("email") as string;
    const password = form.get("password") as string;

    if (!email || !password) {
      return fail(400, { error: "Email and password are required." });
    }

    const user = await db.query.users.findFirst({
      where: eq(users.email, email),
    });

    if (!user || !user.password) {
      return fail(400, { error: "Invalid email or password." });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return fail(400, { error: "Invalid email or password." });
    }

    // Block unverified users
    if (!user.emailVerified) {
      return fail(400, {
        error: "Please verify your email before signing in. Check your inbox.",
      });
    }

    // Create database session
    const sessionToken = crypto.randomUUID();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await db.insert(sessions).values({
      sessionToken,
      userId: user.id,
      expires,
    });

    // Set session cookie (same name Auth.js uses)
    cookies.set("authjs.session-token", sessionToken, {
      path: "/",
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      expires,
    });

    throw redirect(303, "/dashboard");
  },
};
