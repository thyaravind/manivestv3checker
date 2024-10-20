<script lang="ts">
  export let disabled: boolean = false;
</script>

<button
  on:click
  {disabled}
  class="w-full bg-blue-500 text-white px-6 py-3 rounded-lg font-semibold transition-all duration-300 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
>
  <slot />
</button>