<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { createScan, listScans, deleteScan } from '$lib/api.js';
  import ScanStatus from '$lib/components/ScanStatus.svelte';

  let domain = '';
  let scans = [];
  let loading = false;
  let error = '';
  let deleteConfirm = null; // id du scan en attente de confirmation
  let homographWarning = null; // { explanation, domain, punycode } si confirmation requise

  onMount(async () => {
    try {
      scans = await listScans();
    } catch {
      // silencieux au chargement
    }
  });

  async function startScan(d, confirm = false) {
    loading = true;
    error = '';
    try {
      const result = await createScan(d, confirm);
      if (result.needsConfirmation) {
        // Domaine homographe : on n'enchaîne pas, on affiche l'avertissement.
        homographWarning = result;
        loading = false;
        return;
      }
      goto(`/scan/${result.id}`);
    } catch (e) {
      error = e.message;
      loading = false;
    }
  }

  async function handleSubmit() {
    const d = domain.trim();
    if (!d) return;
    homographWarning = null;
    await startScan(d);
  }

  function confirmHomograph() {
    // « Scanner quand même » : ré-émet la requête avec la confirmation explicite.
    const target = homographWarning.domain;
    homographWarning = null;
    startScan(target, true);
  }

  function cancelHomograph() {
    homographWarning = null;
    loading = false;
  }

  async function handleDelete(id) {
    if (deleteConfirm !== id) {
      deleteConfirm = id;
      setTimeout(() => { if (deleteConfirm === id) deleteConfirm = null; }, 3000);
      return;
    }
    deleteConfirm = null;
    try {
      await deleteScan(id);
      scans = scans.filter(s => s.id !== id);
    } catch (e) {
      error = `Could not delete: ${e.message}`;
    }
  }

  function formatDate(iso) {
    return new Date(iso).toLocaleString('en-US', {
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
    <p>Passive security audit for your domain</p>
  </header>

  <section class="scan-form">
    <form on:submit|preventDefault={handleSubmit}>
      <div class="input-row">
        <input
          type="text"
          bind:value={domain}
          placeholder="example.com"
          disabled={loading}
          autocomplete="off"
          spellcheck="false"
        />
        <button type="submit" disabled={loading || !domain.trim()}>
          {#if loading}
            <span class="spinner"></span> Scanning…
          {:else}
            Scan
          {/if}
        </button>
      </div>
      {#if error}
        <p class="error" role="alert">⚠ {error}</p>
      {/if}
    </form>

    {#if homographWarning}
      <div class="homograph-warning" role="alert">
        <h3>⚠ Domaine homographe détecté</h3>
        <p class="homograph-explain">{homographWarning.explanation}</p>
        <dl class="homograph-forms">
          <div>
            <dt>Forme saisie</dt>
            <dd>{homographWarning.domain}</dd>
          </div>
          <div>
            <dt>Forme réelle scannée (Punycode)</dt>
            <dd><code>{homographWarning.punycode}</code></dd>
          </div>
        </dl>
        <div class="homograph-actions">
          <button type="button" class="cancel" on:click={cancelHomograph}>
            Annuler
          </button>
          <button type="button" class="force" on:click={confirmHomograph}>
            Scanner quand même
          </button>
        </div>
      </div>
    {/if}
  </section>

  {#if scans.length > 0}
    <section class="history">
      <h2>Recent scans</h2>
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
            <button
              class="delete-btn"
              class:confirm={deleteConfirm === scan.id}
              on:click={() => handleDelete(scan.id)}
              title={deleteConfirm === scan.id ? 'Click again to confirm' : 'Delete'}
            >
              {deleteConfirm === scan.id ? '?' : '✕'}
            </button>
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

  header { text-align: center; margin-bottom: 40px; }
  h1 { font-size: 2rem; font-weight: 800; margin: 0 0 8px; color: #f8fafc; }
  header p { color: #64748b; margin: 0; }

  .scan-form {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 28px;
    margin-bottom: 40px;
  }
  .input-row { display: flex; gap: 10px; }
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
    display: flex;
    align-items: center;
    gap: 8px;
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

  .spinner {
    width: 14px; height: 14px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .error {
    color: #f87171;
    font-size: 0.875rem;
    margin: 10px 0 0;
    background: #450a0a44;
    border-left: 3px solid #ef4444;
    padding: 8px 12px;
    border-radius: 0 4px 4px 0;
  }

  .homograph-warning {
    margin-top: 20px;
    background: #422006;
    border: 1px solid #b45309;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 18px 20px;
  }
  .homograph-warning h3 {
    margin: 0 0 10px;
    color: #fbbf24;
    font-size: 1rem;
    font-weight: 700;
  }
  .homograph-explain {
    margin: 0 0 14px;
    color: #fde68a;
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .homograph-forms {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 0 0 16px;
  }
  .homograph-forms div { display: flex; flex-direction: column; gap: 2px; }
  .homograph-forms dt {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #d97706;
    font-weight: 600;
  }
  .homograph-forms dd {
    margin: 0;
    font-size: 0.95rem;
    color: #fef3c7;
    word-break: break-all;
  }
  .homograph-forms code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #1c1206;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .homograph-actions { display: flex; gap: 10px; justify-content: flex-end; }
  .homograph-actions button {
    border: none;
    border-radius: 8px;
    padding: 10px 18px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }
  .homograph-actions .cancel {
    background: #334155;
    color: #e2e8f0;
  }
  .homograph-actions .cancel:hover { background: #475569; }
  .homograph-actions .force {
    background: #dc2626;
    color: #fff;
  }
  .homograph-actions .force:hover { background: #b91c1c; }

  .history h2 {
    color: #94a3b8;
    margin: 0 0 16px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 0.8rem;
    font-weight: 600;
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
    min-width: 0;
  }
  .scan-link:hover { background: #263548; }

  .scan-domain { font-weight: 600; font-size: 0.95rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .scan-score  { font-size: 0.85rem; color: #64748b; flex-shrink: 0; }
  .scan-date   { font-size: 0.75rem; color: #475569; white-space: nowrap; flex-shrink: 0; }

  .scan-grade { font-size: 1.1rem; font-weight: 800; width: 28px; text-align: center; flex-shrink: 0; }
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
    transition: color 0.15s, background 0.15s;
    flex-shrink: 0;
  }
  .delete-btn:hover { color: #f87171; }
  .delete-btn.confirm { color: #f97316; font-weight: 700; font-size: 1rem; }
</style>
