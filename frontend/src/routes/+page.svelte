<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { createScan, listScans, deleteScan } from '$lib/api.js';
  import ScanStatus from '$lib/components/ScanStatus.svelte';

  let domain = '';
  let scans = [];
  let loading = false;
  let error = '';

  onMount(async () => {
    try {
      scans = await listScans();
    } catch (e) {
      // silencieux au chargement
    }
  });

  async function handleSubmit() {
    if (!domain.trim()) return;
    loading = true;
    error = '';
    try {
      const scan = await createScan(domain.trim());
      goto(`/scan/${scan.id}`);
    } catch (e) {
      error = e.message;
      loading = false;
    }
  }

  async function handleDelete(id) {
    try {
      await deleteScan(id);
      scans = scans.filter(s => s.id !== id);
    } catch (e) {
      error = e.message;
    }
  }

  function formatDate(iso) {
    return new Date(iso).toLocaleString('fr-FR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }
</script>

<svelte:head>
  <title>SecurityScoreCard</title>
</svelte:head>

<main>
  <header>
    <h1>🔐 SecurityScoreCard</h1>
    <p>Audit passif de sécurité pour votre domaine</p>
  </header>

  <section class="scan-form">
    <form on:submit|preventDefault={handleSubmit}>
      <div class="input-row">
        <input
          type="text"
          bind:value={domain}
          placeholder="exemple.com"
          disabled={loading}
          autocomplete="off"
          spellcheck="false"
        />
        <button type="submit" disabled={loading || !domain.trim()}>
          {loading ? 'Lancement…' : 'Scanner'}
        </button>
      </div>
      {#if error}
        <p class="error">{error}</p>
      {/if}
    </form>
  </section>

  {#if scans.length > 0}
    <section class="history">
      <h2>Scans récents</h2>
      <div class="scan-list">
        {#each scans as scan (scan.id)}
          <div class="scan-row">
            <a href="/scan/{scan.id}" class="scan-link">
              <span class="scan-domain">{scan.domain}</span>
              <ScanStatus status={scan.status} />
              {#if scan.grade}
                <span class="scan-grade grade-{scan.grade}">{scan.grade}</span>
              {/if}
              {#if scan.score != null}
                <span class="scan-score">{scan.score}/100</span>
              {/if}
              <span class="scan-date">{formatDate(scan.created_at)}</span>
            </a>
            <button class="delete-btn" on:click={() => handleDelete(scan.id)} title="Supprimer">✕</button>
          </div>
        {/each}
      </div>
    </section>
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
    max-width: 780px;
    margin: 0 auto;
    padding: 48px 20px;
  }

  header {
    text-align: center;
    margin-bottom: 40px;
  }
  h1 {
    font-size: 2rem;
    font-weight: 800;
    margin: 0 0 8px;
    color: #f8fafc;
  }
  header p {
    color: #64748b;
    margin: 0;
  }

  .scan-form {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 28px;
    margin-bottom: 40px;
  }
  .input-row {
    display: flex;
    gap: 10px;
  }
  input {
    flex: 1;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px 16px;
    font-size: 1rem;
    color: #e2e8f0;
    outline: none;
    transition: border-color 0.2s;
  }
  input:focus { border-color: #3b82f6; }
  input:disabled { opacity: 0.5; }

  button[type="submit"] {
    background: #3b82f6;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 12px 24px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
    white-space: nowrap;
  }
  button[type="submit"]:hover:not(:disabled) { background: #2563eb; }
  button[type="submit"]:disabled { opacity: 0.5; cursor: not-allowed; }

  .error {
    color: #f87171;
    font-size: 0.875rem;
    margin: 10px 0 0;
  }

  .history h2 {
    font-size: 1.1rem;
    font-weight: 600;
    color: #94a3b8;
    margin: 0 0 16px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 0.8rem;
  }
  .scan-list { display: flex; flex-direction: column; gap: 8px; }

  .scan-row {
    display: flex;
    align-items: center;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    overflow: hidden;
  }
  .scan-link {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    text-decoration: none;
    color: inherit;
    transition: background 0.15s;
  }
  .scan-link:hover { background: #263548; }

  .scan-domain { font-weight: 600; font-size: 0.95rem; flex: 1; }
  .scan-score  { font-size: 0.85rem; color: #64748b; }
  .scan-date   { font-size: 0.75rem; color: #475569; white-space: nowrap; }

  .scan-grade {
    font-size: 1.1rem;
    font-weight: 800;
    width: 28px;
    text-align: center;
  }
  .grade-A { color: #22c55e; }
  .grade-B { color: #84cc16; }
  .grade-C { color: #eab308; }
  .grade-D { color: #f97316; }
  .grade-F { color: #ef4444; }

  .delete-btn {
    background: none;
    border: none;
    padding: 12px 14px;
    color: #475569;
    cursor: pointer;
    font-size: 0.8rem;
    transition: color 0.15s;
  }
  .delete-btn:hover { color: #f87171; }
</style>
