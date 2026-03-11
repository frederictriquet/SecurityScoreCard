<script>
  export let finding;

  const sev = {
    critical: { label: 'Critique', cls: 'critical' },
    high:     { label: 'Élevé',    cls: 'high'     },
    medium:   { label: 'Moyen',    cls: 'medium'   },
    low:      { label: 'Faible',   cls: 'low'      },
    info:     { label: 'Info',     cls: 'info'     }
  };

  $: cfg = sev[finding.severity] ?? sev.info;
  let expanded = false;
</script>

<div class="finding">
  <button class="header" on:click={() => (expanded = !expanded)}>
    <span class="sev {cfg.cls}">{cfg.label}</span>
    <span class="title">{finding.title}</span>
    <span class="chevron" class:open={expanded}>›</span>
  </button>
  {#if expanded}
    <div class="body">
      <p class="desc">{finding.description}</p>
      {#if finding.remediation}
        <div class="remed">
          <span class="remed-label">Remédiation :</span>
          {finding.remediation}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .finding {
    border-left: 3px solid #374151;
    margin-bottom: 6px;
    border-radius: 0 4px 4px 0;
    overflow: hidden;
    background: #111827;
  }
  .finding:has(.critical) { border-color: #ef4444; }
  .finding:has(.high)     { border-color: #f97316; }
  .finding:has(.medium)   { border-color: #eab308; }
  .finding:has(.low)      { border-color: #60a5fa; }
  .finding:has(.info)     { border-color: #6b7280; }

  .header {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    background: none;
    border: none;
    cursor: pointer;
    text-align: left;
    color: inherit;
  }
  .header:hover { background: #1f2937; }

  .sev {
    flex-shrink: 0;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .critical { background: #450a0a; color: #fca5a5; }
  .high     { background: #431407; color: #fdba74; }
  .medium   { background: #422006; color: #fde68a; }
  .low      { background: #172554; color: #93c5fd; }
  .info     { background: #1f2937; color: #9ca3af; }

  .title {
    flex: 1;
    font-size: 0.875rem;
    color: #e5e7eb;
  }
  .chevron {
    color: #6b7280;
    font-size: 1.1rem;
    transition: transform 0.2s;
    transform: rotate(0deg);
  }
  .chevron.open { transform: rotate(90deg); }

  .body {
    padding: 10px 14px 12px;
    border-top: 1px solid #1f2937;
  }
  .desc {
    font-size: 0.825rem;
    color: #9ca3af;
    margin: 0 0 8px;
    line-height: 1.5;
  }
  .remed {
    font-size: 0.8rem;
    color: #6b7280;
    line-height: 1.4;
  }
  .remed-label {
    color: #4ade80;
    font-weight: 600;
    margin-right: 4px;
  }
</style>
