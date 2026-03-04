<script lang="ts">
  import { signIn } from "@auth/sveltekit/client";
  import { page } from "$app/state";
  import googleIcon from "$lib/assets/google.svg";
  import githubIcon from "$lib/assets/github.svg";

  let { form } = $props();

  let showPassword = $state(false);

  const errorParam = $derived(page.url.searchParams.get("error"));
  const registered = $derived(page.url.searchParams.get("registered"));
  const verified = $derived(page.url.searchParams.get("verified"));
  const reset = $derived(page.url.searchParams.get("reset"));

  const oauthError = $derived(
    errorParam === "OAuthAccountNotLinked"
      ? "This email is already linked to another account."
      : errorParam
        ? "An error occurred. Please try again."
        : null
  );
</script>

<div class="min-h-[calc(100vh-56px)] flex items-center justify-center bg-gray-50 px-4 py-8">
  <div class="w-full max-w-md bg-white p-6 sm:p-8 rounded-2xl shadow-lg">
    <h1 class="text-2xl sm:text-3xl font-bold mb-6 text-center text-gray-900">Welcome Back</h1>

    {#if registered}
      <div class="mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm">
        Account created! Please check your email to verify your account before signing in.
      </div>
    {/if}

    {#if verified}
      <div class="mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm">
        Email verified successfully! You can now sign in.
      </div>
    {/if}

    {#if reset}
      <div class="mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm">
        Password reset successfully! Please sign in with your new password.
      </div>
    {/if}

    {#if oauthError}
      <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">
        {oauthError}
      </div>
    {/if}

    {#if form?.error}
      <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">
        {form.error}
      </div>
    {/if}

    <form method="POST" class="space-y-4">
      <div>
        <label for="email" class="block text-sm font-medium text-gray-700 mb-1">Email</label>
        <input
          id="email"
          name="email"
          type="email"
          placeholder="you@email.com"
          required
          class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none"
        />
      </div>

      <div>
        <label for="password" class="block text-sm font-medium text-gray-700 mb-1">Password</label>
        <div class="relative">
          <input
            id="password"
            name="password"
            type={showPassword ? "text" : "password"}
            placeholder="••••••••"
            required
            class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none pr-16"
          />
          <button
            type="button"
            onclick={() => (showPassword = !showPassword)}
            class="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-gray-500 hover:text-gray-700 font-medium"
          >
            {showPassword ? "Hide" : "Show"}
          </button>
        </div>
      </div>

      <div class="flex justify-end">
        <a href="/forgot-password" class="text-sm text-blue-600 hover:underline">
          Forgot password?
        </a>
      </div>

      <button
        type="submit"
        class="w-full bg-blue-600 hover:bg-blue-700 text-white p-2.5 rounded-lg transition font-medium"
      >
        Sign In
      </button>
    </form>

    <!-- OAuth divider -->
    <div class="mt-6">
      <div class="relative">
        <div class="absolute inset-0 flex items-center">
          <div class="w-full border-t border-gray-300"></div>
        </div>
        <div class="relative flex justify-center text-sm">
          <span class="bg-white px-2 text-gray-500">Or continue with</span>
        </div>
      </div>

      <div class="mt-4 flex flex-col sm:flex-row gap-3">
        <button
          onclick={() => signIn("google", { redirectTo: "/dashboard" })}
          class="flex-1 flex items-center justify-center gap-2 bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 p-2.5 rounded-lg transition"
        >
          <img src={googleIcon} alt="Google" class="w-5 h-5" />
          Google
        </button>

        <button
          onclick={() => signIn("github", { redirectTo: "/dashboard" })}
          class="flex-1 flex items-center justify-center gap-2 bg-gray-900 hover:bg-gray-800 text-white p-2.5 rounded-lg transition"
        >
          <img src={githubIcon} alt="GitHub" class="w-5 h-5 invert" />
          GitHub
        </button>
      </div>
    </div>

    <p class="mt-6 text-center text-sm text-gray-600">
      Don't have an account?
      <a href="/register" class="text-blue-600 hover:underline font-medium">Create one</a>
    </p>
  </div>
</div>
