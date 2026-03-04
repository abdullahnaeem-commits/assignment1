<script lang="ts">
  let { data, form } = $props();

  let name = $state(data.user?.name || "");
  let email = $state(data.user?.email || "");
  let currentPassword = $state("");
  let newPassword = $state("");
  let confirmPassword = $state("");
  let showPasswords = $state(false);
  let showEditForm = $state(false);

  const passwordMismatch = $derived(
    confirmPassword.length > 0 && newPassword !== confirmPassword
  );
</script>

<div class="min-h-[calc(100vh-56px)] bg-gray-50 p-4 sm:p-6 md:p-8">
  <div class="max-w-2xl mx-auto">
    <h1 class="text-2xl sm:text-3xl font-bold text-gray-900 mb-2">Profile</h1>
    <p class="text-gray-600 mb-6 sm:mb-8">Manage your account information</p>

    {#if form?.success}
      <div class="mb-4 p-3 bg-green-100 text-green-700 rounded-lg text-sm">
        Profile updated successfully!
      </div>
    {/if}

    {#if form?.error}
      <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg text-sm">
        {form.error}
      </div>
    {/if}

    <!-- Account Info (read-only) -->
    <div class="bg-white p-5 sm:p-6 rounded-2xl shadow mb-4 sm:mb-6">
      <h2 class="text-lg font-semibold text-gray-900 mb-4">Account Information</h2>
      <div class="space-y-3 text-sm">
        {#if data.user?.createdAt}
          <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1 py-2 border-b border-gray-100">
            <span class="text-gray-500">Member since</span>
            <span class="text-gray-900 font-medium">
              {new Date(data.user.createdAt).toLocaleDateString("en-US", {
                year: "numeric",
                month: "long",
                day: "numeric",
              })}
            </span>
          </div>
        {/if}
        <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1 py-2 border-b border-gray-100">
          <span class="text-gray-500">Auth method</span>
          <span class="text-gray-900 font-medium">
            {data.isOAuth ? (data.provider === "google" ? "Google" : data.provider === "github" ? "GitHub" : "OAuth") : "Email & Password"}
          </span>
        </div>
      </div>
    </div>

    <!-- Edit Profile Toggle Button -->
    {#if !showEditForm}
      <button
        onclick={() => (showEditForm = true)}
        class="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 text-white px-6 py-2.5 rounded-lg transition font-medium mb-4 sm:mb-6"
      >
        Edit Profile
      </button>
    {/if}

    <!-- Editable Profile -->
    {#if showEditForm}
      <div class="bg-white p-5 sm:p-6 rounded-2xl shadow mb-4 sm:mb-6">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-semibold text-gray-900">Edit Profile</h2>
          <button
            onclick={() => (showEditForm = false)}
            class="text-sm text-gray-500 hover:text-gray-700 font-medium"
          >
            Cancel
          </button>
        </div>

        <form method="POST" action="?/update" class="space-y-4">
        <div>
          <label for="name" class="block text-sm font-medium text-gray-700 mb-1">
            Display Name
          </label>
          <input
            id="name"
            name="name"
            type="text"
            bind:value={name}
            placeholder="Enter your name"
            class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div>
          <label for="email" class="block text-sm font-medium text-gray-700 mb-1">
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            required
            bind:value={email}
            disabled={data.isOAuth}
            placeholder="you@email.com"
            class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none {data.isOAuth ? 'bg-gray-100 text-gray-500 cursor-not-allowed' : ''}"
          />
          {#if data.isOAuth}
            <p class="text-xs text-gray-400 mt-1">Email is managed by your {data.provider === "google" ? "Google" : "GitHub"} account</p>
          {/if}
        </div>

        <!-- Password Change Section -->
        <div class="pt-4 border-t border-gray-200">
          <h3 class="text-sm font-semibold text-gray-900 mb-3">Change Password</h3>

          {#if data.isOAuth}
            <p class="text-sm text-gray-500">
              Password cannot be changed when signed in with {data.provider === "google" ? "Google" : "GitHub"}.
            </p>
          {:else}
            <div class="space-y-3">
              <div>
                <label for="currentPassword" class="block text-sm font-medium text-gray-700 mb-1">
                  Current Password
                </label>
                <div class="relative">
                  <input
                    id="currentPassword"
                    name="currentPassword"
                    type={showPasswords ? "text" : "password"}
                    bind:value={currentPassword}
                    placeholder="••••••••"
                    class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none pr-16"
                  />
                  <button
                    type="button"
                    onclick={() => (showPasswords = !showPasswords)}
                    class="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-gray-500 hover:text-gray-700 font-medium"
                  >
                    {showPasswords ? "Hide" : "Show"}
                  </button>
                </div>
              </div>

              <div>
                <label for="newPassword" class="block text-sm font-medium text-gray-700 mb-1">
                  New Password
                </label>
                <div class="relative">
                  <input
                    id="newPassword"
                    name="newPassword"
                    type={showPasswords ? "text" : "password"}
                    bind:value={newPassword}
                    minlength="6"
                    placeholder="••••••••"
                    class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none"
                  />
                </div>
                {#if newPassword.length > 0 && newPassword.length < 6}
                  <p class="text-red-500 text-xs mt-1">Must be at least 6 characters</p>
                {/if}
              </div>

              <div>
                <label for="confirmPassword" class="block text-sm font-medium text-gray-700 mb-1">
                  Confirm New Password
                </label>
                <input
                  id="confirmPassword"
                  type={showPasswords ? "text" : "password"}
                  bind:value={confirmPassword}
                  minlength="6"
                  placeholder="••••••••"
                  class="w-full border border-gray-300 p-2.5 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 focus:outline-none"
                />
                {#if passwordMismatch}
                  <p class="text-red-500 text-xs mt-1">Passwords don't match</p>
                {/if}
              </div>
            </div>

            <p class="text-xs text-gray-400 mt-2">Leave password fields empty to keep your current password.</p>
          {/if}
        </div>

        <button
          type="submit"
          disabled={passwordMismatch || (newPassword.length > 0 && newPassword.length < 6)}
          class="w-full sm:w-auto bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 disabled:cursor-not-allowed text-white px-6 py-2.5 rounded-lg transition font-medium"
        >
          Save Changes
        </button>
        </form>
      </div>
    {/if}
  </div>
</div>
