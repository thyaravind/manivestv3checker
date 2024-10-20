<script lang="ts">
  export let title: string | undefined = undefined;
</script>

<div class="glass-panel">
  {#if title}
    <h2 class="text-2xl font-bold mb-4 text-gray-800">{title}</h2>
  {/if}
  <slot />
</div>

<style>
  .glass-panel {
    background: white;
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }
</style>