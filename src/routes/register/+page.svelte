<script lang="ts">
  export let form: {
    error?: string;
  };
</script>

<div class="min-h-screen flex items-center justify-center bg-gray-100">
  <div class="w-full max-w-md bg-white p-8 rounded-2xl shadow-lg">

    <h1 class="text-3xl font-bold mb-6 text-center">
      Create Account
    </h1>

    {#if form?.error}
      <div class="mb-4 p-3 bg-red-100 text-red-700 rounded">
        {form.error}
      </div>
    {/if}

    <form method="POST" class="space-y-4">

      <!-- Name -->
      <div>
        <label class="block text-sm font-medium mb-1">Name</label>
        <input
          name="name"
          type="text"
          class="w-full border border-gray-300 p-2 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none"
          placeholder="John Doe"
        />
      </div>

      <!-- Email -->
      <div>
        <label class="block text-sm font-medium mb-1">Email</label>
        <input
          name="email"
          type="email"
          required
          class="w-full border border-gray-300 p-2 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none"
          placeholder="you@email.com"
        />
      </div>

      <!-- Password -->
      <div>
        <label class="block text-sm font-medium mb-1">Password</label>
        <input
          name="password"
          type="password"
          required
          minlength="6"
          class="w-full border border-gray-300 p-2 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none"
          placeholder="••••••••"
        />
      </div>

      <button
        type="submit"
        class="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded-lg transition"
      >
        Register
      </button>
    </form>

  </div>
</div>