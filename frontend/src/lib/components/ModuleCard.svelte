<script>
  import FindingRow from './FindingRow.svelte';
  import ScanStatus from './ScanStatus.svelte';

  export let module;

  const MODULE_LABELS = {
    dns:        { label: 'DNS Health',    icon: '🌐' },
    tls:        { label: 'TLS / SSL',     icon: '🔒' },
    headers:    { label: 'HTTP Headers',  icon: '📋' },
    reputation: { label: 'IP Réputation', icon: '🛡️' },
    subdomains: { label: 'Sous-domaines', icon: '🗺️' },
    leaks:      { label: 'Fuites (HIBP)', icon: '🔑' }
  };

  $: meta = MODULE_LABELS[module.name] ?? { label: module.name, icon: '🔍' };

  $: scoreColor =
    module.score == null  ? '#6b7280'
    : module.score >= 90  ? '#22c55e'
    : module.score >= 70  ? '#eab308'
    : module.score >= 50  ? '#f97316'
    : '#ef4444';

  $: criticalCount = module.findings?.filter(f => f.severity === 'critical').length ?? 0;
  $: highCount     = module.findings?.filter(f => f.severity === 'high').length ?? 0;
</script>

<div class="card">
  <div class="card-header">
    <span class="icon">{meta.icon}</span>
    <div class="meta">
      <span class="name">{meta.label}</span>
      <div class="badges">
        <ScanStatus status={module.status} />
        {#if criticalCount > 0}
          <span class="badge-crit">{criticalCount} critique{criticalCount > 1 ? 's' : ''}</span>
        {/if}
        {#if highCount > 0}
          <span class="badge-high">{highCount} élevé{highCount > 1 ? 's' : ''}</span>
        {/if}
      </div>
    </div>
    <div class="score-block">
      {#if module.score != null}
        <span class="score-val" style="color:{scoreColor}">{module.score}</span>
        <span class="score-max">/100</span>
      {:else}
        <span class="score-val" style="color:#4b5563">—</span>
      {/if}
    </div>
  </div>

  {#if module.findings?.length > 0}
    <div class="findings">
      {#each module.findings as finding (finding.id)}
        <FindingRow {finding} />
      {/each}
    </div>
  {:else if module.status === 'completed'}
    <p class="no-findings">✅ Aucun problème détecté</p>
  {/if}
</div>

<style>
  .card {
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 8px;
    overflow: hidden;
  }
  .card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 16px;
  }
  .icon { font-size: 1.4rem; flex-shrink: 0; }
  .meta { flex: 1; }
  .name {
    font-weight: 600;
    font-size: 0.95rem;
    color: #f3f4f6;
    display: block;
    margin-bottom: 4px;
  }
  .badges { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  .badge-crit {
    font-size: 0.65rem; font-weight: 700; padding: 2px 7px;
    border-radius: 4px; background: #450a0a; color: #fca5a5;
    text-transform: uppercase;
  }
  .badge-high {
    font-size: 0.65rem; font-weight: 700; padding: 2px 7px;
    border-radius: 4px; background: #431407; color: #fdba74;
    text-transform: uppercase;
  }
  .score-block { display: flex; align-items: baseline; gap: 2px; }
  .score-val { font-size: 1.75rem; font-weight: 800; }
  .score-max { font-size: 0.75rem; color: #6b7280; }

  .findings {
    padding: 0 12px 12px;
    border-top: 1px solid #374151;
    padding-top: 10px;
  }
  .no-findings {
    padding: 10px 16px;
    font-size: 0.825rem;
    color: #4ade80;
    border-top: 1px solid #374151;
    margin: 0;
  }
</style>
