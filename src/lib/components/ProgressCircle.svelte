<script lang="ts">
  export let value: number;
  export let label: string;
  export let color: string;

  $: dashArray = 2 * Math.PI * 45;
  $: dashOffset = dashArray * (1 - value / 100);
</script>

<div class="flex flex-col items-center">
  <svg class="w-24 h-24" viewBox="0 0 100 100">
    <circle
      cx="50"
      cy="50"
      r="45"
      fill="none"
      stroke="#e6e6e6"
      stroke-width="10"
    />
    <circle
      cx="50"
      cy="50"
      r="45"
      fill="none"
      stroke={color}
      stroke-width="10"
      stroke-dasharray={dashArray}
      stroke-dashoffset={dashOffset}
      stroke-linecap="round"
      transform="rotate(-90 50 50)"
    />
    <text x="50" y="50" text-anchor="middle" dy="7" font-size="20" fill="#333">
      {value}%
    </text>
  </svg>
  <span class="mt-2 text-sm font-medium text-gray-600">{label}</span>
</div>