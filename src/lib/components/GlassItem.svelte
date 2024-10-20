<script lang="ts">
  export let status: 'pending' | 'success' | 'warning' | 'error';
</script>

<li class="flex items-center p-3 rounded-lg bg-white shadow-sm">
  {#if status === 'pending'}
    <span class="mr-3 text-yellow-500">⏳</span>
  {:else if status === 'success'}
    <span class="mr-3 text-green-500">✅</span>
  {:else if status === 'warning'}
    <span class="mr-3 text-yellow-500">⚠️</span>
  {:else if status === 'error'}
    <span class="mr-3 text-red-500">❌</span>
  {/if}
  <slot />
</li>