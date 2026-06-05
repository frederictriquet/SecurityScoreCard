<script>
  import { getScanHistory, getScanDiff } from '$lib/api.js';

  /** Current scan id and its domain. */
  export let scanId = '';
  export let domain = '';
  /**
   * Bumped by the parent whenever the scan finishes (or is rescanned) so the
   * history/diff are re-fetched with fresh data.
   */
  export let refreshKey = 0;

  let history = [];
  let diff = null;
  let loaded = false;

  const GRADE_COLOR = {
    A: '#22c55e',
    B: '#84cc16',
    C: '#eab308',
    D: '#f97316',
    F: '#ef4444'
  };

  function gradeColor(grade) {
    return GRADE_COLOR[grade] ?? '#64748b';
  }

  function formatDate(iso) {
    if (!iso) return '';
    return new Date(iso).toLocaleString();
  }

  async function load() {
    if (!domain || !scanId) return;
    try {
      [history, diff] = await Promise.all([
        getScanHistory(domain),
        getScanDiff(scanId)
      ]);
    } catch {
      // History is a non-critical enhancement: stay silent on failure.
      history = [];
      diff = null;
    } finally {
      loaded = true;
    }
  }

  // Re-load whenever the scan changes or the parent signals completion.
  $: scanId, domain, refreshKey, load();

  // Per-scan delta vs the chronologically previous scan (history is sorted
  // most-recent-first, so the previous scan is the next item in the list).
  $: deltas = history.map((s, i) => {
    const prev = history[i + 1];
    if (!prev || s.score == null || prev.score == null) return null;
    return s.score - prev.score;
  });

  $: hasFindingDiff =
    diff &&
    ((diff.new_findings && diff.new_findings.length > 0) ||
      (diff.resolved_findings && diff.resolved_findings.length > 0));
</script>

{#if loaded && history.length > 1}
  <section class="history">
    <h2>History</h2>

    {#if diff && diff.score_delta != null}
      <p class="summary">
        {#if diff.score_delta > 0}
          <span class="up">▲ Improved by {diff.score_delta} points</span>
        {:else if diff.score_delta < 0}
          <span class="down">▼ Regressed by {Math.abs(diff.score_delta)} points</span>
        {:else}
          <span class="flat">No score change</span>
        {/if}
        {#if diff.grade_change}
          <span class="grade-change">grade {diff.grade_change.replace('->', ' → ')}</span>
        {/if}
        <span class="vs">vs previous scan</span>
      </p>
    {/if}

    <ol class="timeline">
      {#each history as s, i (s.id)}
        <li class:current={s.id === scanId}>
          <span class="grade-pill" style="background:{gradeColor(s.grade)}">
            {s.grade ?? '—'}
          </span>
          <span class="score">{s.score ?? '—'}</span>
          {#if deltas[i] != null}
            {#if deltas[i] > 0}
              <span class="delta up">▲ {deltas[i]}</span>
            {:else if deltas[i] < 0}
              <span class="delta down">▼ {Math.abs(deltas[i])}</span>
            {:else}
              <span class="delta flat">±0</span>
            {/if}
          {/if}
          <span class="date">{formatDate(s.created_at)}</span>
          {#if s.id === scanId}<span class="tag">this scan</span>{/if}
        </li>
      {/each}
    </ol>

    {#if hasFindingDiff}
      <div class="diff-grid">
        {#if diff.new_findings.length > 0}
          <div class="diff-col">
            <h3 class="appeared">Appeared ({diff.new_findings.length})</h3>
            <ul>
              {#each diff.new_findings as f}
                <li><span class="mod">{f.module}</span> {f.title}</li>
              {/each}
            </ul>
          </div>
        {/if}
        {#if diff.resolved_findings.length > 0}
          <div class="diff-col">
            <h3 class="resolved">Resolved ({diff.resolved_findings.length})</h3>
            <ul>
              {#each diff.resolved_findings as f}
                <li><span class="mod">{f.module}</span> {f.title}</li>
              {/each}
            </ul>
          </div>
        {/if}
      </div>
    {/if}
  </section>
{/if}

<style>
  .history {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 32px;
  }
  h2 {
    font-size: 1.1rem;
    font-weight: 700;
    color: #f8fafc;
    margin: 0 0 14px;
  }
  .summary {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    font-size: 0.9rem;
    margin: 0 0 16px;
  }
  .up { color: #4ade80; font-weight: 600; }
  .down { color: #f87171; font-weight: 600; }
  .flat { color: #94a3b8; font-weight: 600; }
  .grade-change {
    color: #cbd5e1;
    background: #0f172a;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 0.8rem;
  }
  .vs { color: #64748b; font-size: 0.8rem; }

  .timeline {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .timeline li {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
    border-radius: 8px;
    background: #0f172a;
  }
  .timeline li.current {
    outline: 1px solid #2563eb66;
    background: #11203a;
  }
  .grade-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    border-radius: 6px;
    color: #0f172a;
    font-weight: 800;
    font-size: 0.85rem;
    flex-shrink: 0;
  }
  .score {
    font-variant-numeric: tabular-nums;
    color: #e2e8f0;
    font-weight: 600;
    min-width: 28px;
  }
  .delta {
    font-size: 0.8rem;
    font-variant-numeric: tabular-nums;
    min-width: 40px;
  }
  .delta.up { color: #4ade80; }
  .delta.down { color: #f87171; }
  .delta.flat { color: #64748b; }
  .date {
    color: #64748b;
    font-size: 0.8rem;
    margin-left: auto;
  }
  .tag {
    background: #1e3a5f;
    color: #93c5fd;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 2px 8px;
    border-radius: 999px;
  }

  .diff-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 16px;
    margin-top: 20px;
  }
  @media (min-width: 700px) {
    .diff-grid { grid-template-columns: 1fr 1fr; }
  }
  .diff-col h3 {
    font-size: 0.85rem;
    margin: 0 0 8px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  h3.appeared { color: #f87171; }
  h3.resolved { color: #4ade80; }
  .diff-col ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .diff-col li {
    font-size: 0.85rem;
    color: #cbd5e1;
    padding: 6px 10px;
    background: #0f172a;
    border-radius: 6px;
  }
  .mod {
    color: #64748b;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-right: 6px;
  }
</style>
