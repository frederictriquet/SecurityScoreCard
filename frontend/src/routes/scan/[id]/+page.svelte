<script>
  import { onMount, onDestroy } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { getScan, createScan, rescanInPlace } from '$lib/api.js';
  import ScoreGauge from '$lib/components/ScoreGauge.svelte';
  import ModuleCard from '$lib/components/ModuleCard.svelte';
  import ScanStatus from '$lib/components/ScanStatus.svelte';

  let scan = null;
  let error = '';
  let interval = null;
  let retries = 0;
  const MAX_RETRIES = 3;
  const POLL_INTERVAL = 2000;

  $: id = $page.params.id;

  async function fetchScan() {
    try {
      scan = await getScan(id);
      retries = 0;
      if (scan.status === 'completed' || scan.status === 'failed') {
        clearInterval(interval);
        interval = null;
      }
    } catch (e) {
      retries++;
      if (retries >= MAX_RETRIES) {
        error = `Impossible de joindre le serveur (${e.message})`;
        clearInterval(interval);
        interval = null;
      }
      // sinon on réessaie silencieusement au prochain tick
    }
  }

  onMount(() => {
    fetchScan();
    interval = setInterval(fetchScan, POLL_INTERVAL);
  });

  onDestroy(() => clearInterval(interval));

  let rescanning = false;

  async function handleRescanNew() {
    if (!scan?.domain || rescanning) return;
    rescanning = true;
    try {
      const newScan = await createScan(scan.domain);
      await goto(`/scan/${newScan.id}`);
      rescanning = false;
    } catch (e) {
      error = e.message;
      rescanning = false;
    }
  }

  async function handleRescanInPlace() {
    if (!scan?.id || rescanning) return;
    rescanning = true;
    try {
      await rescanInPlace(scan.id);
      await fetchScan();
      if (interval === null) {
        interval = setInterval(fetchScan, POLL_INTERVAL);
      }
    } catch (e) {
      error = e.message;
    } finally {
      rescanning = false;
    }
  }

  const MODULE_ORDER = ['dns', 'tls', 'headers', 'reputation', 'subdomains', 'leaks'];

  // Priorité d'affichage : running > pending > completed/failed
  const STATUS_PRIORITY = { running: 0, pending: 1, completed: 2, failed: 2 };

  $: orderedModules = scan?.modules
    ? [...scan.modules].sort((a, b) => {
        const sp = (STATUS_PRIORITY[a.status] ?? 1) - (STATUS_PRIORITY[b.status] ?? 1);
        if (sp !== 0) return sp;
        return MODULE_ORDER.indexOf(a.name) - MODULE_ORDER.indexOf(b.name);
      })
    : [];

  $: completedModules = scan?.modules?.filter(
    m => m.status === 'completed' || m.status === 'failed'
  ).length ?? 0;
  $: totalModules = scan?.modules?.length ?? 0;
  $: progressPct = totalModules > 0 ? Math.round((completedModules / totalModules) * 100) : 0;

  function formatDuration(start, end) {
    if (!start || !end) return null;
    const ms = new Date(end) - new Date(start);
    return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
  }
</script>

<svelte:head>
  <title>{scan ? `${scan.domain} — SecurityScoreCard` : 'Scan en cours…'}</title>
</svelte:head>

<main>
  <nav>
    <a href="/" class="back">← Retour</a>
  </nav>

  {#if error}
    <div class="error-box">{error}</div>
  {:else if !scan}
    <div class="loading">Chargement…</div>
  {:else}
    <header>
      <div class="domain-row">
        <h1>{scan.domain}</h1>
        <ScanStatus status={scan.status} />
        {#if scan.status === 'completed' || scan.status === 'failed'}
          <div class="rescan-group">
            <button class="rescan-btn" on:click={handleRescanNew} disabled={rescanning} title="Créer une nouvelle entrée">
              {#if rescanning}
                <span class="spinner"></span>
              {:else}
                ↺
              {/if}
              Nouveau
            </button>
            <button class="rescan-btn rescan-overwrite" on:click={handleRescanInPlace} disabled={rescanning} title="Écraser ce scan">
              Écraser
            </button>
          </div>
        {/if}
      </div>
      {#if scan.completed_at}
        {@const dur = formatDuration(scan.started_at, scan.completed_at)}
        {#if dur}
          <p class="meta">Scan terminé en {dur}</p>
        {/if}
      {:else if scan.status === 'running'}
        <p class="meta">Scan en cours, résultats disponibles au fil de l'eau…</p>
        <div class="progress-wrap">
          <div class="progress-bar" style="width:{progressPct}%"></div>
        </div>
        <p class="progress-label">{completedModules} / {totalModules} modules terminés</p>
      {/if}
    </header>

    <div class="score-section">
      <ScoreGauge score={scan.score} grade={scan.grade} />
      <div class="score-legend">
        <div class="legend-row"><span class="dot" style="background:#22c55e"></span> A — 90-100</div>
        <div class="legend-row"><span class="dot" style="background:#84cc16"></span> B — 80-89</div>
        <div class="legend-row"><span class="dot" style="background:#eab308"></span> C — 70-79</div>
        <div class="legend-row"><span class="dot" style="background:#f97316"></span> D — 60-69</div>
        <div class="legend-row"><span class="dot" style="background:#ef4444"></span> F — 0-59</div>
      </div>
    </div>

    <div class="modules">
      {#each orderedModules as module (module.id)}
        <ModuleCard {module} />
      {/each}
    </div>
  {/if}
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
  }

  main {
    max-width: 820px;
    margin: 0 auto;
    padding: 32px 20px 60px;
  }

  .back {
    display: inline-block;
    color: #64748b;
    text-decoration: none;
    font-size: 0.875rem;
    margin-bottom: 24px;
    transition: color 0.15s;
  }
  .back:hover { color: #94a3b8; }

  header { margin-bottom: 32px; }
  .domain-row {
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
  }
  .rescan-group {
    display: flex;
    margin-left: auto;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid #334155;
  }
  .rescan-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    background: #1e293b;
    color: #94a3b8;
    border: none;
    border-right: 1px solid #334155;
    padding: 6px 14px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  .rescan-btn:last-child { border-right: none; }
  .rescan-btn:hover:not(:disabled) { background: #263548; color: #e2e8f0; }
  .rescan-btn:disabled { opacity: 0.5; cursor: not-allowed; }
  .rescan-overwrite { color: #64748b; }
  .spinner {
    width: 12px; height: 12px;
    border: 2px solid rgba(148,163,184,0.3);
    border-top-color: #94a3b8;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 {
    font-size: 1.75rem;
    font-weight: 800;
    margin: 0;
    color: #f8fafc;
    word-break: break-all;
  }
  .meta {
    color: #64748b;
    font-size: 0.85rem;
    margin: 6px 0 0;
  }

  .progress-wrap {
    height: 4px;
    background: #1e293b;
    border-radius: 2px;
    margin-top: 10px;
    overflow: hidden;
  }
  .progress-bar {
    height: 100%;
    background: #3b82f6;
    border-radius: 2px;
    transition: width 0.4s ease;
  }
  .progress-label {
    font-size: 0.78rem;
    color: #475569;
    margin: 4px 0 0;
  }

  .score-section {
    display: flex;
    align-items: center;
    gap: 40px;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 28px 32px;
    margin-bottom: 32px;
  }
  .score-legend { display: flex; flex-direction: column; gap: 6px; }
  .legend-row {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.8rem;
    color: #64748b;
  }
  .dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .modules { display: flex; flex-direction: column; gap: 12px; }

  .loading { color: #64748b; padding: 40px; text-align: center; }
  .error-box {
    background: #450a0a;
    color: #f87171;
    padding: 16px;
    border-radius: 8px;
    margin-top: 20px;
  }
</style>
