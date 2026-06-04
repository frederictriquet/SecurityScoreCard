const BASE = '/api';

export async function createScan(domain, confirm = false) {
  const res = await fetch(`${BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, confirm })
  });
  // 409 : domaine homographe non confirmé. Ce n'est pas une erreur mais une
  // demande de confirmation explicite ; on renvoie le détail structuré pour que
  // l'appelant affiche l'avertissement et propose de scanner quand même.
  if (res.status === 409) {
    const err = await res.json().catch(() => ({}));
    if (err.detail && err.detail.needs_confirmation) {
      return { needsConfirmation: true, ...err.detail };
    }
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    // Pydantic renvoie detail comme tableau [{msg, ...}] sur les 422
    const detail = Array.isArray(err.detail)
      ? err.detail.map(e => e.msg).join(', ')
      : err.detail;
    throw new Error(detail || `Erreur ${res.status}`);
  }
  return res.json();
}

export async function getScan(id) {
  const res = await fetch(`${BASE}/scans/${id}`);
  if (!res.ok) throw new Error(`Error ${res.status}`);
  return res.json();
}

export async function listScans() {
  const res = await fetch(`${BASE}/scans`);
  if (!res.ok) throw new Error(`Error ${res.status}`);
  return res.json();
}

export async function rescanInPlace(id) {
  const res = await fetch(`${BASE}/scans/${id}/rescan`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Error ${res.status}`);
  }
  return res.json();
}

export async function deleteScan(id) {
  const res = await fetch(`${BASE}/scans/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`Error ${res.status}`);
}
