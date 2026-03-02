<script lang="ts">
  import { signIn } from "@auth/sveltekit/client";

  let email = "";
  let password = "";

  const login = async () => {
    await signIn("credentials", {
      email,
      password,
      redirectTo: "/dashboard"
    });
  };
</script>

<div class="max-w-md mx-auto bg-white p-8 rounded shadow space-y-4">
  <h1 class="text-2xl font-bold">Login</h1>

  <input bind:value={email} placeholder="Email"
    class="w-full border p-2 rounded" />

  <input type="password" bind:value={password}
    placeholder="Password"
    class="w-full border p-2 rounded" />

  <button on:click={login}
    class="w-full bg-blue-600 text-white p-2 rounded">
    Login
  </button>

  <div class="flex gap-2">
    <button on:click={() => signIn("google")}
      class="flex-1 bg-red-500 text-white p-2 rounded">
      Google
    </button>

    <button on:click={() => signIn("github")}
      class="flex-1 bg-gray-800 text-white p-2 rounded">
      GitHub
    </button>
  </div>
</div>