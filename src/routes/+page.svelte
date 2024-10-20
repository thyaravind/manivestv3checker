<script lang="ts">
  import { verifyExtension } from '$lib/verifier';
  import { onMount } from 'svelte';
  import GlassPanel from '$lib/components/GlassPanel.svelte';
  import GlassButton from '$lib/components/GlassButton.svelte';
  import GlassItem from '$lib/components/GlassItem.svelte';
  import Description from '$lib/components/Description.svelte';

  let file: File | null = null;
  let result: any = null;
  let isVerifying = false;

  async function handleFileChange(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      file = input.files[0];
    }
  }

  async function handleVerify() {
    if (file) {
      isVerifying = true;
      result = await verifyExtension(file);
      isVerifying = false;
    }
  }

  function truncateText(text: string, maxLength: number = 100): string {
    return text.length > maxLength ? text.slice(0, maxLength) + '...' : text;
  }

  onMount(() => {
    console.log('Component mounted');
  });
</script>

<main class="container mx-auto p-8 max-w-6xl">
  <GlassPanel>
    <h1 class="text-3xl font-bold mb-2 text-gray-800">Extension manifest v3 checker</h1>
    <p class="text-gray-600 mb-6">
      This tool verifies browser extensions for compliance with manifest v3 policies. 
      It checks for potential security issues, analyzes permissions, and ensures adherence to best practices. 
      Please help us improve the tool by sending us any false positives or false negatives - utils@21n.io
    </p>
    <div class="mb-8">
      <label for="file-upload" class="block mb-4">
        <input
          id="file-upload"
          type="file"
          accept=".zip"
          on:change={handleFileChange}
          class="hidden"
        />
        <span class="block p-4 text-center text-gray-600 cursor-pointer bg-white rounded-lg shadow-sm border border-gray-200 hover:bg-gray-50 transition-colors">
          {file ? file.name : 'Choose a ZIP file'}
        </span>
      </label>
      <GlassButton on:click={handleVerify} disabled={!file || isVerifying}>
        {#if isVerifying}
          Verifying...
        {:else}
          Verify Extension
        {/if}
      </GlassButton>
    </div>

    {#if result}
      <Description
        manifestVersion={result.manifestVersion}
        description={result.description}
        permissions={result.permissions}
        hostPermissions={result.hostPermissions}
      />

      <GlassPanel title="Verification Results">
        <p class="mb-4 text-gray-600">Total files scanned: {result.totalFiles}</p>
        <ul class="mb-6 space-y-2">
          {#each result.checks as check}
            <GlassItem status={check.status}>
              <span class="text-gray-600">{check.name}</span>
              {#if check.status === 'warning' && check.filesWithIssues}
                <span class="ml-2 text-yellow-600">({check.filesWithIssues} file{check.filesWithIssues > 1 ? 's' : ''} with issues)</span>
              {/if}
            </GlassItem>
          {/each}
        </ul>
        {#if result.warnings.length > 0 || result.errors.length > 0}
          <div class="mt-6">
            <h3 class="text-xl font-bold mb-3 text-gray-800">Issues</h3>
            {#each result.warnings as warning}
              <GlassItem status="warning">
                <div>
                  <p class="text-yellow-600">{truncateText(warning.split('\n')[0], 100)}</p>
                  {#if warning.includes('\n')}
                    <p class="text-sm text-gray-500 mt-1">{truncateText(warning.split('\n')[1], 100)}</p>
                  {/if}
                </div>
              </GlassItem>
            {/each}
            {#each result.errors as error}
              <GlassItem status="error">
                <p class="text-red-600">{truncateText(error, 100)}</p>
              </GlassItem>
            {/each}
          </div>
        {/if}
      </GlassPanel>
    {/if}
  </GlassPanel>
</main>

<style>
  :global(body) {
    background-color: #f0f4f8;
    min-height: 100vh;
    color: #1f2937;
  }
</style>