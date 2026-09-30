/**
 * Spectra Enterprise CBOM Visualizer & Quantum Risk Client Application
 * ====================================================================
 * Interactive, high-performance CycloneDX 1.6 cryptographic telemetry UI.
 */

// Application State
const state = {
  cbom: null,
  components: [],
  vulnerabilities: [],
  dependencies: {},
  filteredComponents: [],
  currentPage: 1,
  pageSize: 50,
  sortCol: 'name',
  sortAsc: true,
  currentSection: 'overview',
  activeComponent: null,
  charts: {},
  mosca: {
    x: 7.0,
    y: 5.0,
    z: 2033, // 2033 - 2026 = ~7 years
  }
};

// DOM References
const elements = {
  headerStatusText: document.getElementById('headerStatusText'),
  headerComponentCount: document.getElementById('headerComponentCount'),
  btnReloadCbom: document.getElementById('btnReloadCbom'),
  fileUploadInput: document.getElementById('fileUploadInput'),
  btnExportJson: document.getElementById('btnExportJson'),
  badgeTotalComps: document.getElementById('badgeTotalComps'),
  badgeMoscaBreaches: document.getElementById('badgeMoscaBreaches'),
  badgeTotalVulns: document.getElementById('badgeTotalVulns'),
  sidebarDomainList: document.getElementById('sidebarDomainList'),
  
  // KPIs
  kpiTotalAssets: document.getElementById('kpiTotalAssets'),
  kpiQuantumSafe: document.getElementById('kpiQuantumSafe'),
  kpiShorVulnerable: document.getElementById('kpiShorVulnerable'),
  kpiMoscaBreached: document.getElementById('kpiMoscaBreached'),
  kpiPolicyVulns: document.getElementById('kpiPolicyVulns'),
  heroPqcScore: document.getElementById('heroPqcScore'),
  heroShorScore: document.getElementById('heroShorScore'),
  quickAssetsTableBody: document.getElementById('quickAssetsTableBody'),

  // Inventory
  inventorySearchInput: document.getElementById('inventorySearchInput'),
  inventoryDomainFilter: document.getElementById('inventoryDomainFilter'),
  inventoryQuantumFilter: document.getElementById('inventoryQuantumFilter'),
  inventoryNistFilter: document.getElementById('inventoryNistFilter'),
  inventoryTableBody: document.getElementById('inventoryTableBody'),
  filteredCountLabel: document.getElementById('filteredCountLabel'),
  pageSizeSelect: document.getElementById('pageSizeSelect'),
  pageInfoLabel: document.getElementById('pageInfoLabel'),
  btnPrevPage: document.getElementById('btnPrevPage'),
  btnNextPage: document.getElementById('btnNextPage'),

  // Mosca
  sliderX: document.getElementById('sliderX'),
  sliderY: document.getElementById('sliderY'),
  sliderZ: document.getElementById('sliderZ'),
  sliderXVal: document.getElementById('sliderXVal'),
  sliderYVal: document.getElementById('sliderYVal'),
  sliderZVal: document.getElementById('sliderZVal'),
  moscaGlobalVerdict: document.getElementById('moscaGlobalVerdict'),
  moscaGlobalGap: document.getElementById('moscaGlobalGap'),
  moscaBreachedCountLabel: document.getElementById('moscaBreachedCountLabel'),
  moscaTableBody: document.getElementById('moscaTableBody'),

  // Vulnerabilities
  vulnerabilitiesGrid: document.getElementById('vulnerabilitiesGrid'),
  vulnCriticalBadge: document.getElementById('vulnCriticalBadge'),
  vulnHighBadge: document.getElementById('vulnHighBadge'),
  vulnMediumBadge: document.getElementById('vulnMediumBadge'),

  // Topology
  topoSourceCol: document.getElementById('topoSourceCol'),
  topoBinaryCol: document.getElementById('topoBinaryCol'),
  topoKeyCol: document.getElementById('topoKeyCol'),
  topoInfraCol: document.getElementById('topoInfraCol'),

  // Raw JSON
  rawJsonCodeBlock: document.getElementById('rawJsonCodeBlock'),
  btnCopyJson: document.getElementById('btnCopyJson'),
  copyJsonBtnText: document.getElementById('copyJsonBtnText'),

  // Detail Drawer
  detailDrawer: document.getElementById('detailDrawer'),
  detailDrawerBackdrop: document.getElementById('detailDrawerBackdrop'),
  btnCloseDrawer: document.getElementById('btnCloseDrawer'),
  drawerTitle: document.getElementById('drawerTitle'),
  drawerSubtitle: document.getElementById('drawerSubtitle'),
  drawerContent: document.getElementById('drawerContent'),
};

// =========================================================================
// 1. DATA INGESTION & PARSING
// =========================================================================

async function fetchCbom() {
  try {
    elements.headerStatusText.textContent = 'Fetching telemetry...';
    const response = await fetch('/api/cbom');
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const data = await response.json();
    processCbomData(data);
  } catch (err) {
    console.warn('[Spectra UI] Failed to load from /api/cbom:', err.message);
    elements.headerStatusText.textContent = 'Upload or connect CBOM';
    elements.rawJsonCodeBlock.textContent = `Error loading CBOM: ${err.message}\n\nPlease click 'Upload JSON' to load your cbom.json file.`;
  }
}

function processCbomData(cbom) {
  state.cbom = cbom;
  state.components = [];
  state.vulnerabilities = cbom.vulnerabilities || [];
  state.dependencies = {};

  if (cbom.dependencies) {
    for (const dep of cbom.dependencies) {
      state.dependencies[dep.ref] = dep.dependsOn || [];
    }
  }

  const rawComps = cbom.components || [];
  for (const c of rawComps) {
    const cp = c.cryptoProperties || {};
    const ap = cp.algorithmProperties || {};
    const props = {};
    if (cp.properties) {
      for (const p of cp.properties) {
        props[p.name] = p.value;
      }
    }

    const domain = ap.executionEnvironment || 'source_code';
    const location = (cp.detectionContext && cp.detectionContext.line) ? cp.detectionContext.line : 'cross-domain';
    const isQuantumSafe = props['crypto:quantumSafe'] === 'true';
    const isShorVulnerable = props['crypto:shorVulnerable'] === 'true';
    const nistStatus = props['crypto:nistStatus'] || 'unknown';

    state.components.push({
      ref: c['bom-ref'] || c.name,
      name: c.name,
      type: c.type,
      primitive: ap.primitive || 'cryptographic_asset',
      algorithm: ap.parameterSetIdentifier || c.name,
      domain: domain,
      location: location,
      keyLength: ap.keyLength || null,
      mode: ap.mode || null,
      curve: ap.curve || null,
      isQuantumSafe: isQuantumSafe,
      isShorVulnerable: isShorVulnerable,
      nistStatus: nistStatus,
      directCalls: parseInt(props['crypto:directCalls'] || '0', 10),
      transitiveCalls: parseInt(props['crypto:transitiveCalls'] || '0', 10),
      callDepth: parseInt(props['crypto:callDepth'] || '0', 10),
      loc: parseInt(props['crypto:loc'] || '0', 10),
      isUpstream: props['crypto:isUpstreamDependency'] === 'true',
      sourceLanguage: props['crypto:sourceLanguage'] || null,
      mosca: {
        riskLevel: props['mosca:riskLevel'] || 'LOW',
        isBreached: props['mosca:inequalityBreached'] === 'true',
        x: parseFloat(props['mosca:shelfLifeX'] || '7.0'),
        y: parseFloat(props['mosca:migrationTimeY'] || '5.0'),
        z: parseFloat(props['mosca:quantumThresholdZ'] || '8.0'),
        sndl: props['mosca:sndlVulnerable'] === 'true',
        recommendedPqc: props['mosca:recommendedPQC'] || (isQuantumSafe ? 'Compliant' : 'ML-KEM / ML-DSA')
      },
      rawProps: props,
      rawComponent: c
    });
  }

  // Update Header Telemetry
  elements.headerStatusText.textContent = `Bound: ${state.components.length} Assets Loaded`;
  elements.headerComponentCount.textContent = `${state.components.length} Components`;
  elements.badgeTotalComps.textContent = state.components.length;
  elements.badgeTotalVulns.textContent = state.vulnerabilities.length;

  const moscaBreaches = state.components.filter(c => c.mosca.isBreached || (c.isShorVulnerable && (state.mosca.x + state.mosca.y > 7.0))).length;
  elements.badgeMoscaBreaches.textContent = moscaBreaches;

  renderAllViews();
}

// =========================================================================
// 2. VIEW CONTROLLER & TAB SWITCHING
// =========================================================================

function switchTab(sectionId) {
  state.currentSection = sectionId;
  document.querySelectorAll('.nav-tab').forEach(tab => {
    if (tab.dataset.section === sectionId) {
      tab.classList.add('active');
    } else {
      tab.classList.remove('active');
    }
  });

  document.querySelectorAll('.section-pane').forEach(pane => {
    if (pane.id === `section-${sectionId}`) {
      pane.classList.add('active');
    } else {
      pane.classList.remove('active');
    }
  });

  // Re-layout active section
  if (sectionId === 'overview') {
    updateCharts();
  }
}

function renderAllViews() {
  renderOverviewKPIs();
  updateCharts();
  renderDomainFilterList();
  applyInventoryFilters();
  renderMoscaSimulator();
  renderVulnerabilities();
  renderTopology();
  renderRawJson();
  lucide.createIcons();
}

// =========================================================================
// 3. EXECUTIVE OVERVIEW RENDERING
// =========================================================================

function renderOverviewKPIs() {
  const total = state.components.length;
  const pqcCount = state.components.filter(c => c.isQuantumSafe).length;
  const shorCount = state.components.filter(c => c.isShorVulnerable).length;
  const moscaBreached = state.components.filter(c => c.mosca.isBreached || (c.isShorVulnerable && (state.mosca.x + state.mosca.y > (state.mosca.z - 2026)))).length;
  const vulnCount = state.vulnerabilities.length;

  elements.kpiTotalAssets.textContent = total.toLocaleString();
  elements.kpiQuantumSafe.textContent = pqcCount.toLocaleString();
  elements.kpiShorVulnerable.textContent = shorCount.toLocaleString();
  elements.kpiMoscaBreached.textContent = moscaBreached.toLocaleString();
  elements.kpiPolicyVulns.textContent = vulnCount.toLocaleString();

  const pqcPct = total > 0 ? ((pqcCount / total) * 100).toFixed(1) : 0;
  const shorPct = total > 0 ? ((shorCount / total) * 100).toFixed(1) : 0;

  elements.heroPqcScore.textContent = `${pqcPct}%`;
  elements.heroShorScore.textContent = `${shorPct}%`;

  // Quick core assets table (first 10 core items)
  const coreAssets = state.components.filter(c => !c.isUpstream && c.domain !== 'runtime').slice(0, 10);
  elements.quickAssetsTableBody.innerHTML = coreAssets.map(c => `
    <tr class="hover:bg-cyber-800/80 cursor-pointer" onclick="openDetailDrawer('${c.ref}')">
      <td class="py-2 px-3 font-bold text-white flex items-center space-x-2">
        <span class="inline-block w-2 h-2 rounded-full ${c.isQuantumSafe ? 'bg-emerald-400' : 'bg-red-400'}"></span>
        <span>${escapeHtml(c.name)}</span>
      </td>
      <td class="py-2 px-3 text-cyan-300">${escapeHtml(c.primitive)}</td>
      <td class="py-2 px-3 text-slate-400 capitalize">${escapeHtml(c.domain.replace('_', ' '))}</td>
      <td class="py-2 px-3 text-slate-400 truncate max-w-[200px]" title="${escapeHtml(c.location)}">${escapeHtml(truncatePath(c.location))}</td>
      <td class="py-2 px-3">${renderNistBadge(c.nistStatus)}</td>
      <td class="py-2 px-3">${renderQuantumBadge(c.isQuantumSafe, c.isShorVulnerable)}</td>
    </tr>
  `).join('');
}

function updateCharts() {
  if (!state.components.length) return;

  // Chart 1: Primitives
  const primCounts = {};
  for (const c of state.components) {
    const p = c.primitive || 'other';
    primCounts[p] = (primCounts[p] || 0) + 1;
  }
  const primLabels = Object.keys(primCounts);
  const primValues = Object.values(primCounts);

  if (state.charts.primitives) state.charts.primitives.destroy();
  const ctxPrim = document.getElementById('chartPrimitives').getContext('2d');
  state.charts.primitives = new Chart(ctxPrim, {
    type: 'doughnut',
    data: {
      labels: primLabels,
      datasets: [{
        data: primValues,
        backgroundColor: ['#06b6d4', '#8b5cf6', '#10b981', '#f59e0b', '#ec4899', '#3b82f6', '#64748b'],
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 9, family: 'JetBrains Mono' }, color: '#94a3b8' } }
      }
    }
  });

  // Chart 2: NIST Status
  const nistCounts = { 'fips_pqc_standard': 0, 'approved': 0, 'deprecated_pqc': 0, 'deprecated_classical': 0, 'broken_classical': 0 };
  for (const c of state.components) {
    const s = c.nistStatus || 'approved';
    nistCounts[s] = (nistCounts[s] || 0) + 1;
  }

  if (state.charts.nist) state.charts.nist.destroy();
  const ctxNist = document.getElementById('chartNistStatus').getContext('2d');
  state.charts.nist = new Chart(ctxNist, {
    type: 'doughnut',
    data: {
      labels: ['PQC Standard', 'Approved', 'Deprecated (PQC)', 'Deprecated (Class.)', 'Broken'],
      datasets: [{
        data: [
          nistCounts.fips_pqc_standard,
          nistCounts.approved,
          nistCounts.deprecated_pqc,
          nistCounts.deprecated_classical,
          nistCounts.broken_classical
        ],
        backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#f97316', '#ef4444'],
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 9, family: 'JetBrains Mono' }, color: '#94a3b8' } }
      }
    }
  });

  // Chart 3: Domains
  const domCounts = { 'source_code': 0, 'artifacts': 0, 'infrastructure': 0, 'network': 0 };
  for (const c of state.components) {
    const d = c.domain || 'source_code';
    domCounts[d] = (domCounts[d] || 0) + 1;
  }

  if (state.charts.domains) state.charts.domains.destroy();
  const ctxDom = document.getElementById('chartDomains').getContext('2d');
  state.charts.domains = new Chart(ctxDom, {
    type: 'bar',
    data: {
      labels: ['Source AST', 'Artifacts', 'IaC / KMS', 'Network'],
      datasets: [{
        label: 'Components',
        data: [domCounts.source_code, domCounts.artifacts, domCounts.infrastructure, domCounts.network],
        backgroundColor: ['#06b6d4', '#8b5cf6', '#10b981', '#f59e0b'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', font: { size: 9, family: 'JetBrains Mono' } } },
        x: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 9, family: 'JetBrains Mono' } } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderDomainFilterList() {
  const domCounts = {};
  for (const c of state.components) {
    domCounts[c.domain] = (domCounts[c.domain] || 0) + 1;
  }

  elements.sidebarDomainList.innerHTML = Object.entries(domCounts).map(([dom, count]) => `
    <div class="flex justify-between items-center px-2 py-1 rounded hover:bg-slate-800 cursor-pointer" onclick="filterBySidebarDomain('${dom}')">
      <span class="text-slate-300 capitalize">${escapeHtml(dom.replace('_', ' '))}</span>
      <span class="px-1.5 py-0.2 rounded bg-cyber-750 text-slate-400 font-bold">${count}</span>
    </div>
  `).join('');
}

function filterBySidebarDomain(domain) {
  elements.inventoryDomainFilter.value = domain;
  switchTab('inventory');
  applyInventoryFilters();
}

// =========================================================================
// 4. INVENTORY EXPLORER
// =========================================================================

function applyInventoryFilters() {
  const search = elements.inventorySearchInput.value.toLowerCase().trim();
  const domain = elements.inventoryDomainFilter.value;
  const quantum = elements.inventoryQuantumFilter.value;
  const nist = elements.inventoryNistFilter.value;

  state.filteredComponents = state.components.filter(c => {
    if (domain !== 'ALL' && c.domain !== domain) return false;
    if (quantum === 'quantum_safe' && !c.isQuantumSafe) return false;
    if (quantum === 'shor_vulnerable' && !c.isShorVulnerable) return false;
    if (nist !== 'ALL' && c.nistStatus !== nist) return false;

    if (search) {
      const match = c.name.toLowerCase().includes(search) ||
                    c.algorithm.toLowerCase().includes(search) ||
                    c.primitive.toLowerCase().includes(search) ||
                    c.location.toLowerCase().includes(search) ||
                    (c.curve && c.curve.toLowerCase().includes(search)) ||
                    (c.mode && c.mode.toLowerCase().includes(search));
      if (!match) return false;
    }
    return true;
  });

  // Sort
  state.filteredComponents.sort((a, b) => {
    let valA = a[state.sortCol] || '';
    let valB = b[state.sortCol] || '';
    if (typeof valA === 'string') valA = valA.toLowerCase();
    if (typeof valB === 'string') valB = valB.toLowerCase();
    if (valA < valB) return state.sortAsc ? -1 : 1;
    if (valA > valB) return state.sortAsc ? 1 : -1;
    return 0;
  });

  state.currentPage = 1;
  renderInventoryTable();
}

function renderInventoryTable() {
  const total = state.filteredComponents.length;
  const totalPages = Math.ceil(total / state.pageSize) || 1;
  if (state.currentPage > totalPages) state.currentPage = totalPages;

  const start = (state.currentPage - 1) * state.pageSize;
  const end = Math.min(start + state.pageSize, total);
  const pageItems = state.filteredComponents.slice(start, end);

  elements.filteredCountLabel.textContent = `Showing ${total ? start + 1 : 0}-${end} of ${total} components`;
  elements.pageInfoLabel.textContent = `Page ${state.currentPage} of ${totalPages}`;
  elements.btnPrevPage.disabled = state.currentPage <= 1;
  elements.btnNextPage.disabled = state.currentPage >= totalPages;

  elements.inventoryTableBody.innerHTML = pageItems.map(c => `
    <tr class="hover:bg-cyber-800/80 cursor-pointer transition border-b border-slate-800" onclick="openDetailDrawer('${c.ref}')">
      <td class="py-2.5 px-3 font-bold text-white flex items-center space-x-2">
        <i data-lucide="${getPrimitiveIcon(c.primitive)}" class="w-3.5 h-3.5 text-cyan-400 shrink-0"></i>
        <span class="truncate max-w-[200px]" title="${escapeHtml(c.name)}">${escapeHtml(c.name)}</span>
      </td>
      <td class="py-2.5 px-3 text-cyan-300 font-semibold">${escapeHtml(c.primitive)}</td>
      <td class="py-2.5 px-3 text-slate-300 text-[11px]">
        ${c.keyLength ? `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 mr-1">${c.keyLength} bits</span>` : ''}
        ${c.mode ? `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-purple-400 mr-1">${escapeHtml(c.mode)}</span>` : ''}
        ${c.curve ? `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-emerald-400 mr-1">${escapeHtml(c.curve)}</span>` : ''}
        ${(!c.keyLength && !c.mode && !c.curve) ? `<span class="text-slate-500">—</span>` : ''}
      </td>
      <td class="py-2.5 px-3 text-slate-400 capitalize">
        <span class="px-2 py-0.5 rounded text-[10px] bg-cyber-750 border border-slate-700">${escapeHtml(c.domain.replace('_', ' '))}</span>
      </td>
      <td class="py-2.5 px-3 text-slate-400 truncate max-w-[240px]" title="${escapeHtml(c.location)}">
        ${escapeHtml(truncatePath(c.location))}
      </td>
      <td class="py-2.5 px-3">${renderNistBadge(c.nistStatus)}</td>
      <td class="py-2.5 px-3">${renderQuantumBadge(c.isQuantumSafe, c.isShorVulnerable)}</td>
      <td class="py-2.5 px-3 text-right">
        <button class="px-2 py-1 rounded bg-cyber-750 hover:bg-cyan-900/50 text-cyan-400 text-[11px] border border-cyan-800/40">
          Inspect
        </button>
      </td>
    </tr>
  `).join('');

  lucide.createIcons();
}

function sortInventory(col) {
  if (state.sortCol === col) {
    state.sortAsc = !state.sortAsc;
  } else {
    state.sortCol = col;
    state.sortAsc = true;
  }
  applyInventoryFilters();
}

// =========================================================================
// 5. MOSCA QUANTUM RISK SIMULATOR
// =========================================================================

function renderMoscaSimulator() {
  const x = state.mosca.x;
  const y = state.mosca.y;
  const zYear = state.mosca.z;
  const currentYear = 2026;
  const z = Math.max(1, zYear - currentYear); // Years until quantum threat

  elements.sliderXVal.textContent = `${x.toFixed(1)} Years`;
  elements.sliderYVal.textContent = `${y.toFixed(1)} Years`;
  elements.sliderZVal.textContent = `${zYear} (${z.toFixed(1)} Yrs)`;

  const isBreached = (x + y) > z;
  const gap = z - (x + y);

  if (isBreached) {
    elements.moscaGlobalVerdict.textContent = `BREACHED (X + Y > Z)`;
    elements.moscaGlobalVerdict.className = 'text-xl font-extrabold text-red-400 mt-1';
    elements.moscaGlobalGap.textContent = `Deficit: ${gap.toFixed(1)} Years (Store-Now-Decrypt-Later Threat)`;
    elements.moscaGlobalGap.className = 'text-[11px] font-mono text-red-300 mt-0.5';
  } else {
    elements.moscaGlobalVerdict.textContent = `SAFE HORIZON (X + Y ≤ Z)`;
    elements.moscaGlobalVerdict.className = 'text-xl font-extrabold text-emerald-400 mt-1';
    elements.moscaGlobalGap.textContent = `Safety Margin: +${gap.toFixed(1)} Years`;
    elements.moscaGlobalGap.className = 'text-[11px] font-mono text-emerald-300 mt-0.5';
  }

  // Filter breached assets: classical asymmetric or Shor vulnerable items
  const vulnerableAssets = state.components.filter(c => c.isShorVulnerable || !c.isQuantumSafe);
  elements.moscaBreachedCountLabel.textContent = `${vulnerableAssets.length} Vulnerable Assets`;

  elements.moscaTableBody.innerHTML = vulnerableAssets.slice(0, 30).map(c => `
    <tr class="hover:bg-cyber-800/80 cursor-pointer" onclick="openDetailDrawer('${c.ref}')">
      <td class="py-2.5 px-3 font-bold text-white flex items-center space-x-2">
        <span class="inline-block w-2 h-2 rounded-full ${isBreached ? 'bg-red-400 animate-pulse' : 'bg-amber-400'}"></span>
        <span class="truncate max-w-[200px]">${escapeHtml(c.name)}</span>
      </td>
      <td class="py-2.5 px-3 text-slate-400 truncate max-w-[220px]" title="${escapeHtml(c.location)}">${escapeHtml(truncatePath(c.location))}</td>
      <td class="py-2.5 px-3 text-amber-300 font-semibold">${x.toFixed(1)}y</td>
      <td class="py-2.5 px-3 text-cyan-300 font-semibold">${y.toFixed(1)}y</td>
      <td class="py-2.5 px-3 text-purple-300 font-semibold">${zYear}</td>
      <td class="py-2.5 px-3">
        <span class="px-2 py-0.5 rounded text-[10px] ${isBreached ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}">
          ${isBreached ? 'IMMINENT BREACH' : 'MONITORED'}
        </span>
      </td>
      <td class="py-2.5 px-3 text-emerald-400 font-bold font-mono">
        ${escapeHtml(c.mosca.recommendedPqc || 'ML-KEM / ML-DSA')}
      </td>
    </tr>
  `).join('');
}

// =========================================================================
// 6. POLICY VIOLATIONS & COMPLIANCE
// =========================================================================

function renderVulnerabilities() {
  const vulns = state.vulnerabilities;
  let crit = 0, high = 0, med = 0;

  for (const v of vulns) {
    const sev = (v.ratings && v.ratings[0] && v.ratings[0].severity) ? v.ratings[0].severity.toLowerCase() : 'medium';
    if (sev === 'critical') crit++;
    else if (sev === 'high') high++;
    else med++;
  }

  elements.vulnCriticalBadge.textContent = `${crit} Critical`;
  elements.vulnHighBadge.textContent = `${high} High`;
  elements.vulnMediumBadge.textContent = `${med} Medium`;

  if (!vulns.length) {
    elements.vulnerabilitiesGrid.innerHTML = `
      <div class="col-span-2 p-8 text-center bg-cyber-850 rounded-xl border border-slate-800 text-slate-400">
        <i data-lucide="shield-check" class="w-10 h-10 text-emerald-400 mx-auto mb-2"></i>
        <p class="font-bold text-white">No Policy Violations Detected</p>
        <p class="text-xs mt-1">All scanned assets adhere to configured cryptographic safety baselines.</p>
      </div>
    `;
    return;
  }

  elements.vulnerabilitiesGrid.innerHTML = vulns.map(v => {
    const sev = (v.ratings && v.ratings[0] && v.ratings[0].severity) ? v.ratings[0].severity.toUpperCase() : 'MEDIUM';
    const sevColor = sev === 'CRITICAL' ? 'red' : (sev === 'HIGH' ? 'amber' : 'blue');
    return `
      <div class="p-4 rounded-xl bg-cyber-850 border border-${sevColor}-900/40 hover:border-${sevColor}-500/50 transition space-y-2">
        <div class="flex items-center justify-between">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-${sevColor}-950 text-${sevColor}-300 border border-${sevColor}-800">
            ${sev}
          </span>
          <span class="text-[10px] font-mono text-slate-500">${escapeHtml(v.id)}</span>
        </div>
        <h4 class="text-xs font-bold text-white">${escapeHtml(v.description || 'Cryptographic compliance violation')}</h4>
        ${v.recommendation ? `<p class="text-[11px] text-slate-400 font-sans">${escapeHtml(v.recommendation)}</p>` : ''}
        ${v.affects ? `<div class="text-[10px] font-mono text-cyan-400 truncate">Target: ${escapeHtml(v.affects.map(a => a.ref).join(', '))}</div>` : ''}
      </div>
    `;
  }).join('');
}

// =========================================================================
// 7. CROSS-DOMAIN TOPOLOGY
// =========================================================================

function renderTopology() {
  const sources = state.components.filter(c => c.domain === 'source_code' && !c.isUpstream).slice(0, 12);
  const binaries = state.components.filter(c => c.domain === 'artifacts' && c.name.includes('Binary')).slice(0, 8);
  const keys = state.components.filter(c => c.domain === 'artifacts' && (c.name.includes('Key') || c.name.includes('Certificate'))).slice(0, 10);
  const infra = state.components.filter(c => c.domain === 'infrastructure' || c.domain === 'network').slice(0, 10);

  elements.topoSourceCol.innerHTML = sources.map(c => `
    <div class="p-2.5 rounded bg-cyber-750 border border-slate-700/60 hover:border-cyan-500/50 cursor-pointer transition" onclick="openDetailDrawer('${c.ref}')">
      <div class="font-bold text-white truncate">${escapeHtml(c.name)}</div>
      <div class="text-[10px] text-cyan-400">${escapeHtml(c.primitive)}</div>
      <div class="text-[9px] text-slate-500 truncate">${escapeHtml(truncatePath(c.location))}</div>
    </div>
  `).join('');

  elements.topoBinaryCol.innerHTML = binaries.map(c => `
    <div class="p-2.5 rounded bg-cyber-750 border border-slate-700/60 hover:border-purple-500/50 cursor-pointer transition" onclick="openDetailDrawer('${c.ref}')">
      <div class="font-bold text-white truncate">${escapeHtml(c.name)}</div>
      <div class="text-[10px] text-purple-400">${escapeHtml(c.algorithm)}</div>
    </div>
  `).join('');

  elements.topoKeyCol.innerHTML = keys.map(c => `
    <div class="p-2.5 rounded bg-cyber-750 border border-slate-700/60 hover:border-emerald-500/50 cursor-pointer transition" onclick="openDetailDrawer('${c.ref}')">
      <div class="font-bold text-white truncate">${escapeHtml(c.name)}</div>
      <div class="text-[10px] text-emerald-400">${escapeHtml(c.algorithm)}</div>
    </div>
  `).join('');

  elements.topoInfraCol.innerHTML = infra.map(c => `
    <div class="p-2.5 rounded bg-cyber-750 border border-slate-700/60 hover:border-amber-500/50 cursor-pointer transition" onclick="openDetailDrawer('${c.ref}')">
      <div class="font-bold text-white truncate">${escapeHtml(c.name)}</div>
      <div class="text-[10px] text-amber-400">${escapeHtml(c.algorithm)}</div>
    </div>
  `).join('');
}

// =========================================================================
// 8. RAW CYCLONEDX JSON VIEWER
// =========================================================================

function renderRawJson() {
  if (!state.cbom) {
    elements.rawJsonCodeBlock.textContent = '// No CBOM loaded.';
    return;
  }
  const formatted = JSON.stringify(state.cbom, null, 2);
  elements.rawJsonCodeBlock.textContent = formatted;
}

// =========================================================================
// 9. DETAIL DRAWER MODAL
// =========================================================================

function openDetailDrawer(ref) {
  const component = state.components.find(c => c.ref === ref);
  if (!component) return;

  state.activeComponent = component;
  elements.drawerTitle.textContent = component.name;
  elements.drawerSubtitle.textContent = `BOM-REF: ${component.ref}`;

  elements.drawerContent.innerHTML = `
    <!-- Top Identity Card -->
    <div class="p-4 rounded-xl bg-cyber-800 border border-slate-700 space-y-2">
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Primitive Type</span>
        <span class="font-bold text-cyan-400 uppercase">${escapeHtml(component.primitive)}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Parameter Set / Algorithm</span>
        <span class="font-bold text-white">${escapeHtml(component.algorithm)}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Domain Environment</span>
        <span class="font-semibold text-slate-300 capitalize">${escapeHtml(component.domain.replace('_', ' '))}</span>
      </div>
      ${component.keyLength ? `<div class="flex justify-between items-center"><span class="text-slate-400">Key Length</span><span class="text-cyan-300 font-bold">${component.keyLength} bits</span></div>` : ''}
      ${component.mode ? `<div class="flex justify-between items-center"><span class="text-slate-400">Block Cipher Mode</span><span class="text-purple-300">${escapeHtml(component.mode)}</span></div>` : ''}
      ${component.curve ? `<div class="flex justify-between items-center"><span class="text-slate-400">Elliptic Curve</span><span class="text-emerald-300">${escapeHtml(component.curve)}</span></div>` : ''}
    </div>

    <!-- NIST & Quantum Classification -->
    <div class="p-4 rounded-xl bg-cyber-800 border border-slate-700 space-y-2">
      <h4 class="text-xs font-bold text-slate-400 uppercase">Compliance & Quantum Risk</h4>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">NIST Standard Status</span>
        <span>${renderNistBadge(component.nistStatus)}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Quantum-Safe Assurance</span>
        <span class="font-bold ${component.isQuantumSafe ? 'text-emerald-400' : 'text-red-400'}">${component.isQuantumSafe ? 'YES (FIPS 203/204/205 / AES-256)' : 'NO'}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Shor Algorithm Vulnerable</span>
        <span class="font-bold ${component.isShorVulnerable ? 'text-red-400' : 'text-emerald-400'}">${component.isShorVulnerable ? 'YES (Vulnerable to Quantum Factorization)' : 'NO'}</span>
      </div>
    </div>

    <!-- Mosca Assessment -->
    <div class="p-4 rounded-xl bg-cyber-800 border border-slate-700 space-y-2">
      <h4 class="text-xs font-bold text-amber-400 uppercase">Michele Mosca's Risk Evaluation</h4>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Risk Severity Level</span>
        <span class="font-bold ${component.mosca.riskLevel === 'CRITICAL' ? 'text-red-400' : 'text-amber-400'}">${component.mosca.riskLevel}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">SNDL Exposure</span>
        <span class="font-bold ${component.mosca.sndl ? 'text-red-400' : 'text-slate-400'}">${component.mosca.sndl ? 'Store-Now-Decrypt-Later' : 'Standard'}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-slate-400">PQC Replacement Path</span>
        <span class="font-bold text-emerald-400">${escapeHtml(component.mosca.recommendedPqc)}</span>
      </div>
    </div>

    <!-- Code Detection Context & Blast Radius -->
    <div class="p-4 rounded-xl bg-cyber-800 border border-slate-700 space-y-2">
      <h4 class="text-xs font-bold text-cyan-400 uppercase">Blast Radius & Detection Context</h4>
      <div class="space-y-1">
        <span class="text-slate-400 block">Exact Code Location:</span>
        <div class="p-2 rounded bg-cyber-900 border border-slate-800 text-cyan-300 break-all select-all font-mono text-[11px]">
          ${escapeHtml(component.location)}
        </div>
      </div>
      <div class="grid grid-cols-3 gap-2 pt-2 text-center">
        <div class="p-2 rounded bg-cyber-900 border border-slate-800">
          <div class="text-lg font-bold text-white">${component.directCalls}</div>
          <div class="text-[9px] text-slate-500 uppercase">Direct Calls</div>
        </div>
        <div class="p-2 rounded bg-cyber-900 border border-slate-800">
          <div class="text-lg font-bold text-white">${component.transitiveCalls}</div>
          <div class="text-[9px] text-slate-500 uppercase">Transitive Calls</div>
        </div>
        <div class="p-2 rounded bg-cyber-900 border border-slate-800">
          <div class="text-lg font-bold text-white">${component.callDepth}</div>
          <div class="text-[9px] text-slate-500 uppercase">Call Depth</div>
        </div>
      </div>
    </div>

    <!-- Raw Properties Object -->
    <div class="p-4 rounded-xl bg-cyber-800 border border-slate-700 space-y-2">
      <h4 class="text-xs font-bold text-slate-400 uppercase">CycloneDX 1.6 Ext Properties</h4>
      <div class="max-h-48 overflow-y-auto space-y-1">
        ${Object.entries(component.rawProps).map(([k, v]) => `
          <div class="flex justify-between items-center py-0.5 border-b border-slate-800 text-[10px]">
            <span class="text-slate-400 font-mono">${escapeHtml(k)}:</span>
            <span class="text-cyan-300 font-mono font-bold truncate max-w-[240px]">${escapeHtml(String(v))}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  elements.detailDrawer.classList.remove('translate-x-full');
  elements.detailDrawerBackdrop.classList.remove('hidden');
}

function closeDetailDrawer() {
  elements.detailDrawer.classList.add('translate-x-full');
  elements.detailDrawerBackdrop.classList.add('hidden');
  state.activeComponent = null;
}

// =========================================================================
// 10. HELPER FORMATTERS & BADGES
// =========================================================================

function renderNistBadge(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'fips_pqc_standard') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-pqc">FIPS PQC</span>`;
  } else if (s === 'approved') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-approved">APPROVED</span>`;
  } else if (s === 'deprecated_pqc') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-deprecated">DEPR. PQC</span>`;
  } else if (s === 'deprecated_classical') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-deprecated">DEPR. CLASS</span>`;
  } else if (s === 'broken_classical') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-broken">BROKEN</span>`;
  }
  return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">UNKNOWN</span>`;
}

function renderQuantumBadge(isQuantumSafe, isShorVulnerable) {
  if (isQuantumSafe) {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-pqc flex items-center space-x-1 w-fit"><i data-lucide="shield-check" class="w-3 h-3 inline"></i><span>PQC SAFE</span></span>`;
  } else if (isShorVulnerable) {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-shor flex items-center space-x-1 w-fit"><i data-lucide="unlock" class="w-3 h-3 inline"></i><span>SHOR RISK</span></span>`;
  }
  return `<span class="px-2 py-0.5 rounded text-[10px] font-bold badge-approved flex items-center space-x-1 w-fit"><span>CLASSICAL</span></span>`;
}

function getPrimitiveIcon(primitive) {
  const p = String(primitive || '').toLowerCase();
  if (p.includes('key')) return 'key';
  if (p.includes('cipher')) return 'lock';
  if (p.includes('signature')) return 'feather';
  if (p.includes('hash')) return 'hash';
  if (p.includes('certificate')) return 'file-badge';
  if (p.includes('secure_transport') || p.includes('protocol')) return 'shield';
  if (p.includes('prng')) return 'shuffle';
  return 'cpu';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function truncatePath(path) {
  if (!path) return '';
  const parts = path.replace(/\\/g, '/').split('/');
  if (parts.length <= 3) return path;
  return '.../' + parts.slice(-3).join('/');
}

// =========================================================================
// 11. EVENT LISTENERS
// =========================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Navigation
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      switchTab(tab.dataset.section);
    });
  });

  // Reload
  elements.btnReloadCbom.addEventListener('click', fetchCbom);

  // File Upload
  elements.fileUploadInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target.result);
        processCbomData(parsed);
        // Post to server so it updates active state
        fetch('/api/cbom', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed)
        }).catch(() => {});
      } catch (err) {
        alert('Invalid CBOM JSON file: ' + err.message);
      }
    };
    reader.readAsText(file);
  });

  // Export JSON
  elements.btnExportJson.addEventListener('click', () => {
    if (!state.cbom) return;
    const blob = new Blob([JSON.stringify(state.cbom, null, 2)], { type: 'application/json' });
    const u = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = u;
    a.download = 'cbom.json';
    a.click();
    URL.revokeObjectURL(u);
  });

  // Copy JSON
  elements.btnCopyJson.addEventListener('click', () => {
    if (!state.cbom) return;
    navigator.clipboard.writeText(JSON.stringify(state.cbom, null, 2)).then(() => {
      elements.copyJsonBtnText.textContent = 'Copied!';
      setTimeout(() => { elements.copyJsonBtnText.textContent = 'Copy to Clipboard'; }, 2000);
    });
  });

  // Inventory Filters
  elements.inventorySearchInput.addEventListener('input', applyInventoryFilters);
  elements.inventoryDomainFilter.addEventListener('change', applyInventoryFilters);
  elements.inventoryQuantumFilter.addEventListener('change', applyInventoryFilters);
  elements.inventoryNistFilter.addEventListener('change', applyInventoryFilters);
  elements.pageSizeSelect.addEventListener('change', (e) => {
    state.pageSize = parseInt(e.target.value, 10);
    state.currentPage = 1;
    renderInventoryTable();
  });

  elements.btnPrevPage.addEventListener('click', () => {
    if (state.currentPage > 1) {
      state.currentPage--;
      renderInventoryTable();
    }
  });

  elements.btnNextPage.addEventListener('click', () => {
    const totalPages = Math.ceil(state.filteredComponents.length / state.pageSize);
    if (state.currentPage < totalPages) {
      state.currentPage++;
      renderInventoryTable();
    }
  });

  // Mosca Sliders
  elements.sliderX.addEventListener('input', (e) => {
    state.mosca.x = parseFloat(e.target.value);
    renderMoscaSimulator();
  });
  elements.sliderY.addEventListener('input', (e) => {
    state.mosca.y = parseFloat(e.target.value);
    renderMoscaSimulator();
  });
  elements.sliderZ.addEventListener('input', (e) => {
    state.mosca.z = parseInt(e.target.value, 10);
    renderMoscaSimulator();
  });

  // Detail Drawer
  elements.btnCloseDrawer.addEventListener('click', closeDetailDrawer);
  elements.detailDrawerBackdrop.addEventListener('click', closeDetailDrawer);

  // Initial Fetch
  fetchCbom();
});
