import { db } from "$lib/db";
import { users } from "$lib/schema";
import bcrypt from "bcrypt";
import { fail } from "@sveltejs/kit";

export const actions = {
  default: async ({ request }: any) => {
    const form = await request.formData();
    const name = form.get("name") as string;
    const email = form.get("email") as string;
    const password = form.get("password") as string;

    if (!email || !password) {
      return fail(400, { error: "Email and password are required." });
    }

    try {
      const hashed = await bcrypt.hash(password, 12);

      await db.insert(users).values({
        name,
        email,
        password: hashed,
      });

      return { success: true };
    } catch (err: any) {
      console.error("Registration error:", err);

      if (err?.code === "23505") {
        return fail(400, { error: "An account with this email already exists." });
      }

      return fail(500, { error: "Registration failed. Check server logs." });
    }
  },
};