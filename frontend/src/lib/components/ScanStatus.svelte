<script>
  /** @type {'pending'|'running'|'completed'|'failed'} */
  export let status = 'pending';

  const config = {
    pending:   { label: 'En attente',  cls: 'pending'   },
    running:   { label: 'En cours…',   cls: 'running'   },
    completed: { label: 'Terminé',     cls: 'completed' },
    failed:    { label: 'Échec',       cls: 'failed'    }
  };

  $: cfg = config[status] ?? config.pending;
</script>

<span class="badge {cfg.cls}">{cfg.label}</span>

<style>
  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .pending   { background: #374151; color: #9ca3af; }
  .running   { background: #1e3a5f; color: #60a5fa; animation: pulse 1.5s infinite; }
  .completed { background: #14532d; color: #4ade80; }
  .failed    { background: #450a0a; color: #f87171; }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.6; }
  }
</style>
