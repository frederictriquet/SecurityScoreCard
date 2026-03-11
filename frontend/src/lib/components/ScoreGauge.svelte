<script>
  /** @type {number|null} */
  export let score = null;
  /** @type {string|null} */
  export let grade = null;

  const SIZE = 160;
  const STROKE = 14;
  const R = (SIZE - STROKE) / 2;
  const CIRCUMFERENCE = 2 * Math.PI * R;

  $: pct = score != null ? Math.max(0, Math.min(100, score)) / 100 : 0;
  $: dash = pct * CIRCUMFERENCE;
  $: gap = CIRCUMFERENCE - dash;

  $: color =
    score == null ? '#4b5563'
    : score >= 90 ? '#22c55e'
    : score >= 80 ? '#84cc16'
    : score >= 70 ? '#eab308'
    : score >= 60 ? '#f97316'
    : '#ef4444';
</script>

<div class="gauge" style="width:{SIZE}px;height:{SIZE}px">
  <svg width={SIZE} height={SIZE} viewBox="0 0 {SIZE} {SIZE}">
    <!-- Track -->
    <circle
      cx={SIZE / 2} cy={SIZE / 2} r={R}
      fill="none" stroke="#1f2937" stroke-width={STROKE}
    />
    <!-- Progress -->
    <circle
      cx={SIZE / 2} cy={SIZE / 2} r={R}
      fill="none"
      stroke={color}
      stroke-width={STROKE}
      stroke-dasharray="{dash} {gap}"
      stroke-linecap="round"
      transform="rotate(-90 {SIZE/2} {SIZE/2})"
      style="transition: stroke-dasharray 0.6s ease"
    />
  </svg>
  <div class="center">
    {#if grade}
      <span class="grade" style="color:{color}">{grade}</span>
      <span class="score">{score}/100</span>
    {:else}
      <span class="grade" style="color:{color}">—</span>
    {/if}
  </div>
</div>

<style>
  .gauge {
    position: relative;
    display: inline-block;
  }
  .center {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
  .grade {
    font-size: 2.5rem;
    font-weight: 800;
    line-height: 1;
  }
  .score {
    font-size: 0.75rem;
    color: #9ca3af;
    margin-top: 2px;
  }
</style>
