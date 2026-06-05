import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

const REPO_URL = 'https://github.com/frederictriquet/SecurityScoreCard';

const MODULE_LABELS = {
  dns:        'DNS Health',
  tls:        'TLS / SSL',
  headers:    'HTTP Headers',
  reputation: 'IP Reputation',
  subdomains: 'Subdomains',
  leaks:      'Leaks (HIBP)',
  ports:      'Ports & WHOIS'
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEV_COLORS = {
  critical: [220, 38, 38],
  high:     [249, 115, 22],
  medium:   [234, 179, 8],
  low:      [96, 165, 250],
  info:     [156, 163, 175]
};

const GRADE_COLORS = {
  A: [34, 197, 94],
  B: [132, 204, 22],
  C: [234, 179, 8],
  D: [249, 115, 22],
  F: [239, 68, 68]
};

/**
 * Generates and downloads a PDF report for a given scan.
 * @param {object} scan - Full scan object (domain, score, grade, modules, findings…)
 */
export function downloadPdf(scan) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 14;
  let y = 20;

  // --- Title ---
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('Security Audit Report', margin, y);
  y += 10;

  doc.setFontSize(12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100);
  doc.text(scan.domain, margin, y);
  y += 6;

  if (scan.completed_at) {
    doc.setFontSize(9);
    doc.text(`Scan completed: ${new Date(scan.completed_at).toLocaleString()}`, margin, y);
  }
  y += 10;

  // --- Overall score ---
  const gradeColor = GRADE_COLORS[scan.grade] ?? [100, 100, 100];
  doc.setFontSize(40);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(...gradeColor);
  doc.text(scan.grade ?? '—', margin, y + 2);

  doc.setFontSize(14);
  doc.setTextColor(60);
  doc.text(`${scan.score ?? '—'} / 100`, margin + 25, y + 2);

  doc.setFontSize(9);
  doc.setTextColor(120);
  doc.text('Overall Score', margin + 25, y + 8);
  y += 18;

  // --- Separator line ---
  doc.setDrawColor(200);
  doc.line(margin, y, pageWidth - margin, y);
  y += 8;

  // --- Per-module summary ---
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(40);
  doc.text('Module Summary', margin, y);
  y += 6;

  const modules = [...(scan.modules ?? [])].sort(
    (a, b) => (SEV_ORDER[a.name] ?? 99) - (SEV_ORDER[b.name] ?? 99)
  );

  const summaryRows = modules.map(m => {
    const findings = m.findings ?? [];
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'low').length;
    return [
      MODULE_LABELS[m.name] ?? m.name,
      m.score != null ? `${m.score}/100` : '—',
      String(findings.length),
      String(critical),
      String(high),
      String(medium),
      String(low)
    ];
  });

  autoTable(doc, {
    startY: y,
    margin: { left: margin, right: margin },
    head: [['Module', 'Score', 'Findings', 'Critical', 'High', 'Medium', 'Low']],
    body: summaryRows,
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [226, 232, 240], fontSize: 8 },
    bodyStyles: { fontSize: 8 },
    columnStyles: {
      0: { cellWidth: 35 },
      1: { halign: 'center' },
      2: { halign: 'center' },
      3: { halign: 'center' },
      4: { halign: 'center' },
      5: { halign: 'center' },
      6: { halign: 'center' }
    }
  });

  y = doc.lastAutoTable.finalY + 12;

  // --- Detailed findings per module ---
  for (const mod of modules) {
    const findings = [...(mod.findings ?? [])].sort(
      (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
    );
    if (findings.length === 0) continue;

    // Check the remaining space
    if (y > 260) {
      doc.addPage();
      y = 20;
    }

    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(40);
    doc.text(MODULE_LABELS[mod.name] ?? mod.name, margin, y);
    y += 5;

    const rows = findings.map(f => [
      (f.severity ?? 'info').toUpperCase(),
      f.title ?? '',
      f.description ?? '',
      f.remediation ?? ''
    ]);

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Severity', 'Finding', 'Description', 'Remediation']],
      body: rows,
      theme: 'striped',
      headStyles: { fillColor: [30, 41, 59], textColor: [226, 232, 240], fontSize: 7.5 },
      bodyStyles: { fontSize: 7, cellPadding: 2 },
      columnStyles: {
        0: { cellWidth: 16, halign: 'center', fontStyle: 'bold' },
        1: { cellWidth: 35 },
        2: { cellWidth: 65 },
        3: { cellWidth: 50 }
      },
      didParseCell(data) {
        if (data.section === 'body' && data.column.index === 0) {
          const sev = data.cell.raw.toLowerCase();
          const color = SEV_COLORS[sev];
          if (color) data.cell.styles.textColor = color;
        }
      }
    });

    y = doc.lastAutoTable.finalY + 10;
  }

  // --- Footer ---
  const pageCount = doc.internal.getNumberOfPages();
  doc.setFontSize(7);
  doc.setTextColor(160);
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    const pageH = doc.internal.pageSize.getHeight();
    doc.text(
      `SecurityScoreCard — ${scan.domain} — Page ${i}/${pageCount}`,
      pageWidth / 2, pageH - 8,
      { align: 'center' }
    );
    doc.setTextColor(100, 130, 200);
    doc.textWithLink(REPO_URL, pageWidth / 2, pageH - 4, {
      align: 'center',
      url: REPO_URL
    });
    doc.setTextColor(160);
  }

  doc.save(`audit-${scan.domain}-${new Date().toISOString().slice(0, 10)}.pdf`);
}
