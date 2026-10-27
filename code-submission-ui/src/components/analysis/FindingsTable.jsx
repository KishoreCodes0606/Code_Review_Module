import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Filter,
  ListFilter,
  Search,
  ShieldCheck,
  Table2,
  X,
} from 'lucide-react';
import { CATEGORY_LABEL, SeverityBadge, severityRank } from './common';

const PAGE_SIZE = 50;

function sortFindings(findings, sortBy) {
  const copy = [...findings];
  if (sortBy === 'line') {
    copy.sort((a, b) => (a.line_start || 0) - (b.line_start || 0));
  } else if (sortBy === 'rule') {
    copy.sort((a, b) => String(a.rule_id).localeCompare(String(b.rule_id)));
  } else {
    copy.sort((a, b) =>
      (b.severity_score ?? 0) - (a.severity_score ?? 0) ||
      severityRank(a.severity) - severityRank(b.severity)
    );
  }
  return copy;
}

function SortHeader({ label, active, activeDir, onClick }) {
  return (
    <th scope="col" className="px-2 py-2 text-left">
      <button
        type="button"
        onClick={onClick}
        className={`inline-flex items-center gap-1 font-semibold uppercase tracking-wider text-[10px] transition-colors rounded px-1 py-0.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
          active ? 'text-indigo-300' : 'text-slate-400 hover:text-slate-200'
        }`}
      >
        {label}
        {active ? (
          activeDir === 'asc'
            ? <ChevronUp className="w-3 h-3" />
            : <ChevronDown className="w-3 h-3" />
        ) : (
          <ListFilter className="w-3 h-3 opacity-50" />
        )}
      </button>
    </th>
  );
}

export function FindingsTable({ findings, onViewDetails, selectedFindingId, runStatus }) {
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [agent, setAgent] = useState('');
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('severity');
  const [page, setPage] = useState(0);

  const severities = useMemo(
    () => [...new Set(findings.map((f) => f.severity).filter(Boolean))],
    [findings]
  );
  const agents = useMemo(
    () => [...new Set(findings.map((f) => f.source_agent).filter(Boolean))],
    [findings]
  );

  // Reset pagination whenever inputs/filters change size
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (severity && f.severity !== severity) return false;
      if (category && f.category !== category) return false;
      if (agent && f.source_agent !== agent) return false;
      if (q) {
        const hay = `${f.title || ''} ${f.description || ''} ${f.rule_id || ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [findings, severity, category, agent, query]);

  const sorted = useMemo(() => sortFindings(filtered, sortBy), [filtered, sortBy]);
  const pageCount = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = sorted.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  const onFilterChange = (setter) => (e) => {
    setter(e.target.value);
    setPage(0);
  };

  if (!findings.length) {
    const incomplete = Boolean(runStatus) && runStatus !== 'COMPLETED';
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-10 text-center">
        {incomplete ? (
          <>
            <AlertTriangle className="w-10 h-10 text-amber-400 mx-auto mb-3" />
            <h3 className="text-sm font-bold text-amber-300">No findings reported — but this run is {runStatus}</h3>
            <p className="mt-1 text-xs text-slate-400 max-w-xl mx-auto">
              One or more agents could not complete, so this empty list is <strong>not</strong> a clean
              scan. Check the agent results and the detection-coverage notes in the summary above,
              fix the reported issue, then re-run the analysis.
            </p>
          </>
        ) : (
          <>
            <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
            <h3 className="text-sm font-bold text-emerald-300">No findings reported</h3>
            <p className="mt-1 text-xs text-slate-400 max-w-xl mx-auto">
              The backend returned an empty findings list for this run and every agent reported
              <span className="font-mono"> succeeded</span>. Note that M2 only implements the rule
              sets listed in the detection-coverage notes — absence of a finding is not a guarantee
              that no issue exists.
            </p>
          </>
        )}
      </div>
    );
  }

  const hasFilters = severity || category || agent || query;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2.5 bg-slate-950/70 border-b border-slate-800">
        <span className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-slate-400">
          <Filter className="w-3.5 h-3.5" /> Filters
        </span>

        <select
          value={severity}
          onChange={onFilterChange(setSeverity)}
          aria-label="Filter by severity"
          className="bg-slate-900 border border-slate-700/80 rounded-md px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All severities</option>
          {severities.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <select
          value={category}
          onChange={onFilterChange(setCategory)}
          aria-label="Filter by category"
          className="bg-slate-900 border border-slate-700/80 rounded-md px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
        >
          <option value="">All categories</option>
          <option value="security">Security</option>
          <option value="quality">Code Quality</option>
        </select>

        {agents.length > 0 && (
          <select
            value={agent}
            onChange={onFilterChange(setAgent)}
            aria-label="Filter by source agent"
            className="bg-slate-900 border border-slate-700/80 rounded-md px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
          >
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        )}

        <div className="relative flex-1 min-w-[180px]">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="search"
            value={query}
            onChange={onFilterChange(setQuery)}
            placeholder="Search title / description / rule ID…"
            aria-label="Search findings"
            className="w-full bg-slate-900 border border-slate-700/80 rounded-md pl-8 pr-7 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
          {query && (
            <button
              type="button"
              onClick={() => { setQuery(''); setPage(0); }}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-200"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        <span className="text-[11px] font-mono text-slate-400 shrink-0">
          {sorted.length}/{findings.length} findings
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="bg-slate-950 border-b border-slate-800">
            <tr className="text-slate-400">
              <SortHeader label="Severity" active={sortBy === 'severity'} activeDir="desc"
                onClick={() => { setSortBy('severity'); setPage(0); }} />
              <th scope="col" className="px-2 py-2 text-left font-semibold uppercase tracking-wider text-[10px]">Category</th>
              <SortHeader label="Finding" active={sortBy === 'rule'} activeDir="asc"
                onClick={() => { setSortBy('rule'); setPage(0); }} />
              <th scope="col" className="px-2 py-2 text-left font-semibold uppercase tracking-wider text-[10px]">File</th>
              <SortHeader label="Lines" active={sortBy === 'line'} activeDir="asc"
                onClick={() => { setSortBy('line'); setPage(0); }} />
              <th scope="col" className="px-2 py-2 text-left font-semibold uppercase tracking-wider text-[10px]">Agent</th>
              <th scope="col" className="px-2 py-2 text-left font-semibold uppercase tracking-wider text-[10px]">Details</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.map((f) => (
              <tr
                key={f.id}
                className={`border-b border-slate-800/60 transition-colors ${
                  selectedFindingId === f.id ? 'bg-indigo-500/10' : 'hover:bg-slate-800/40'
                }`}
              >
                <td className="px-2 py-2 whitespace-nowrap">
                  <SeverityBadge severity={f.severity} score={f.severity_score} />
                </td>
                <td className="px-2 py-2 whitespace-nowrap">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                      f.category === 'security'
                        ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                        : f.category === 'quality'
                        ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                        : 'bg-slate-500/10 text-slate-300 border-slate-500/30'
                    }`}
                  >
                    {CATEGORY_LABEL[f.category] || f.category}
                  </span>
                </td>
                <td className="px-2 py-2 max-w-[320px]">
                  <div className="truncate text-slate-100" title={f.description}>
                    {f.title}
                  </div>
                  <div className="font-mono text-[10px] text-slate-500 truncate">{f.rule_id}</div>
                </td>
                <td className="px-2 py-2 font-mono text-[11px] text-slate-300 max-w-[160px] truncate" title={f.file_path}>
                  {f.file_path || '—'}
                </td>
                <td className="px-2 py-2 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                  {f.line_start === f.line_end || f.line_end == null
                    ? f.line_start
                    : `${f.line_start}–${f.line_end}`}
                </td>
                <td className="px-2 py-2 text-[11px] text-slate-400 whitespace-nowrap">
                  {f.source_agent || '—'}
                </td>
                <td className="px-2 py-2">
                  <button
                    type="button"
                    onClick={() => onViewDetails(f)}
                    className="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-indigo-600 text-slate-200 hover:text-white text-[11px] font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500"
                  >
                    View Details
                  </button>
                </td>
              </tr>
            ))}
            {!filtered.length && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-slate-400">
                  No findings match the current filters — clear one or more filters to see all{' '}
                  {findings.length} findings.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination (only shown when there is more than one page) */}
      {pageCount > 1 && (
        <div className="flex items-center justify-between px-3 py-2 border-t border-slate-800 bg-slate-950/70 text-[11px] text-slate-400">
          <span>
            Page {safePage + 1} of {pageCount} · showing {pageRows.length} of {sorted.length}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={safePage === 0}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={safePage >= pageCount - 1}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default FindingsTable;
