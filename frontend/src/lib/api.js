const BASE = '/api';

export async function createScan(domain, confirm = false) {
  const res = await fetch(`${BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, confirm })
  });
  // 409: unconfirmed homograph domain. This is not an error but a request for
  // explicit confirmation; we return the structured detail so the caller can
  // display the warning and offer to scan anyway.
  if (res.status === 409) {
    const err = await res.json().catch(() => ({}));
    if (err.detail && err.detail.needs_confirmation) {
      return { needsConfirmation: true, ...err.detail };
    }
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    // Pydantic returns detail as an array [{msg, ...}] on 422 responses
    const detail = Array.isArray(err.detail)
      ? err.detail.map(e => e.msg).join(', ')
      : err.detail;
    throw new Error(detail || `Error ${res.status}`);
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

export async function getScanHistory(domain) {
  const res = await fetch(`${BASE}/scans/history?domain=${encodeURIComponent(domain)}`);
  if (!res.ok) throw new Error(`Error ${res.status}`);
  return res.json();
}

export async function getScanDiff(id) {
  const res = await fetch(`${BASE}/scans/${id}/diff`);
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
