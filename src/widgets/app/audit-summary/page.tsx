'use client';

import { useTheme, useWidgetState, useWidgetSDK } from '@nitrostack/widgets';

interface AuditFindingData {
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  issue?: string;
  source?: string;
  remediation?: string;
}

export default function AuditSummary() {
  const theme = useTheme();
  const { getToolOutput } = useWidgetSDK();
  const [state, setState] = useWidgetState<{ compact: boolean }>(() => ({
    compact: false
  }));

  const data = getToolOutput<AuditFindingData>();
  const isDark = theme === 'dark';

  if (!data) {
    return (
      <div style={{
        padding: '20px',
        color: isDark ? '#f8fafc' : '#111827',
        fontFamily: 'Inter, system-ui, sans-serif'
      }}>
        Loading audit summary...
      </div>
    );
  }

  const severity = data.severity ?? 'INFO';
  const severityColor: Record<string, string> = {
    CRITICAL: '#dc2626',
    HIGH: '#ea580c',
    MEDIUM: '#ca8a04',
    LOW: '#2563eb',
    INFO: '#475569'
  };

  return (
    <section style={{
      width: '100%',
      maxWidth: '460px',
      padding: '20px',
      border: `1px solid ${isDark ? '#334155' : '#d1d5db'}`,
      borderRadius: '8px',
      background: isDark ? '#0f172a' : '#ffffff',
      color: isDark ? '#f8fafc' : '#111827',
      fontFamily: 'Inter, system-ui, sans-serif'
    }}>
      <header style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        marginBottom: '16px'
      }}>
        <div>
          <p style={{ margin: 0, fontSize: '12px', color: isDark ? '#94a3b8' : '#64748b' }}>
            DroidSec Auditor
          </p>
          <h2 style={{ margin: '4px 0 0', fontSize: '18px', lineHeight: 1.25 }}>
            {data.issue ?? 'Security finding'}
          </h2>
        </div>
        <span style={{
          flex: '0 0 auto',
          padding: '6px 10px',
          borderRadius: '999px',
          background: severityColor[severity] ?? severityColor.INFO,
          color: '#ffffff',
          fontSize: '12px',
          fontWeight: 700
        }}>
          {severity}
        </span>
      </header>

      <dl style={{ margin: 0, display: 'grid', gap: '10px' }}>
        <div>
          <dt style={{ fontSize: '12px', color: isDark ? '#94a3b8' : '#64748b' }}>Source</dt>
          <dd style={{ margin: '3px 0 0', fontSize: '14px' }}>{data.source ?? 'Unknown source'}</dd>
        </div>

        {!state?.compact && (
          <div>
            <dt style={{ fontSize: '12px', color: isDark ? '#94a3b8' : '#64748b' }}>Remediation</dt>
            <dd style={{ margin: '3px 0 0', fontSize: '14px', lineHeight: 1.45 }}>
              {data.remediation ?? 'Review the finding and apply the recommended secure configuration.'}
            </dd>
          </div>
        )}
      </dl>

      <button
        type="button"
        onClick={() => setState({ compact: !state?.compact })}
        style={{
          marginTop: '16px',
          padding: '8px 12px',
          border: `1px solid ${isDark ? '#475569' : '#cbd5e1'}`,
          borderRadius: '6px',
          background: isDark ? '#1e293b' : '#f8fafc',
          color: isDark ? '#f8fafc' : '#111827',
          cursor: 'pointer',
          fontSize: '13px'
        }}
      >
        {state?.compact ? 'Show remediation' : 'Hide remediation'}
      </button>
    </section>
  );
}
