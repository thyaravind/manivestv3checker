<script lang="ts">
  export let manifestVersion: number;
  export let description: string;
  export let permissions: string[];
  export let hostPermissions: string[];

  $: hasHostPermissions = hostPermissions.length > 0;
</script>

<div class="bg-white rounded-lg p-4 shadow-sm mb-6">
  <h3 class="text-xl font-semibold mb-2">Extension Details</h3>
  <p class="mb-2"><strong>Manifest Version:</strong> {manifestVersion}</p>
  <p class="mb-2"><strong>Description:</strong> {description}</p>
  
  <div class="mb-2">
    <strong>Permissions:</strong>
    {#if permissions.length > 0}
      <ul class="list-disc list-inside">
        {#each permissions as permission}
          <li>{permission}</li>
        {/each}
      </ul>
    {:else}
      <p>No specific permissions requested.</p>
    {/if}
  </div>

  <div class="mb-2">
    <strong>Host Permissions:</strong>
    {#if hostPermissions.length > 0}
      <ul class="list-disc list-inside">
        {#each hostPermissions as hostPermission}
          <li>{hostPermission}</li>
        {/each}
      </ul>
      <p class="text-yellow-600 mt-2">
        ⚠️ This extension requests host permissions, which may result in longer review times by extension stores.
      </p>
    {:else}
      <p>No host permissions requested.</p>
    {/if}
  </div>
</div>