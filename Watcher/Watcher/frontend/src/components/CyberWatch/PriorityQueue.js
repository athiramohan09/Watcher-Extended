import React, { Component } from 'react';
import axios from 'axios';
import { Button } from 'react-bootstrap';

// Patch First - AI risk scoring / vulnerability prioritisation.
// Lists stored CVEs sorted by risk_score (highest first), the score
// computed in cyber_watch/core.py: calculate_risk_score():
//   KEV +40, EPSS * 30, (CVSS/10) * 20, published in last 30 days +10,
//   capped 0-100. P1 >= 80, P2 60-79, P3 40-59, P4 < 40.
// EPSS is FIRST's pre-trained machine-learning model (probability of
// exploitation in the next 30 days). KEV means CISA lists the CVE as
// known exploited in the wild. A KEV CVE therefore outranks a
// higher-CVSS CVE that nobody is exploiting.
// Data comes from /api/cyber_watch/cves/?ordering=-risk_score, with
// the Knox token (localStorage 'token'), the same as DailyReports.
// If a CVE has never been scored (run enrich_risk_scores first) its
// risk_score is null and it sorts last with a "Not scored yet" note.
const authHeaders = () => {
    const token = localStorage.getItem('token');
    return token ? { Authorization: `Token ${token}` } : {};
};

const PRIORITY_BADGE = {
    P1: 'bg-danger',
    P2: 'bg-warning text-dark',
    P3: 'bg-info text-dark',
    P4: 'bg-secondary',
};

const getCveUrl = (id) => {
    if (!id) return '#';
    if (id.startsWith('CVE-')) return `https://www.cve.org/CVERecord?id=${id}`;
    return `https://vulnerability.circl.lu/vuln/${id}`;
};

class PriorityQueue extends Component {
    constructor(props) {
        super(props);
        this.state = {
            cves: [],
            loading: true,
            error: '',
            onlyKev: false,
            onlyHighEpss: false,
            priority: 'ALL',
        };
    }

    componentDidMount() {
        this.fetchQueue();
    }

    fetchQueue = () => {
        this.setState({ loading: true, error: '' });
        axios.get('/api/cyber_watch/cves/?ordering=-risk_score', { headers: authHeaders() })
            .then(res => {
                const data = Array.isArray(res.data) ? res.data : (res.data.results || []);
                // Defensive client-side sort: highest risk first, unscored last.
                data.sort((a, b) => (b.risk_score ?? -1) - (a.risk_score ?? -1));
                this.setState({ cves: data, loading: false });
            })
            .catch(err => this.setState({
                loading: false,
                error: err.response?.data?.detail || 'Could not load the priority queue. Run enrich_risk_scores first, then refresh.',
            }));
    };

    filtered = () => {
        const { cves, onlyKev, onlyHighEpss, priority } = this.state;
        return cves.filter(c => {
            if (onlyKev && !c.is_kev) return false;
            if (onlyHighEpss && !(c.epss_score != null && c.epss_score > 0.5)) return false;
            if (priority !== 'ALL' && c.priority !== priority) return false;
            return true;
        });
    };

    renderPriorityBadge = (priority) => {
        if (!priority) return <span className="text-muted">-</span>;
        return <span className={`badge ${PRIORITY_BADGE[priority] || 'bg-secondary'}`}>{priority}</span>;
    };

    render() {
        const { loading, error, onlyKev, onlyHighEpss, priority } = this.state;
        const rows = this.filtered().slice(0, 20);
        const scored = this.state.cves.filter(c => c.risk_score != null).length;

        return (
            <div>
                <div className="d-flex flex-wrap gap-2 align-items-center mb-2">
                    <label className="form-check-label small">
                        <input type="checkbox" className="form-check-input me-1"
                            checked={onlyKev} onChange={e => this.setState({ onlyKev: e.target.checked })} />
                        Only KEV
                    </label>
                    <label className="form-check-label small">
                        <input type="checkbox" className="form-check-input me-1"
                            checked={onlyHighEpss} onChange={e => this.setState({ onlyHighEpss: e.target.checked })} />
                        Only EPSS &gt; 50%
                    </label>
                    <select className="form-select form-select-sm" style={{ width: 130 }}
                        value={priority} onChange={e => this.setState({ priority: e.target.value })}>
                        <option value="ALL">All priorities</option>
                        <option value="P1">P1 only</option>
                        <option value="P2">P2 only</option>
                        <option value="P3">P3 only</option>
                        <option value="P4">P4 only</option>
                    </select>
                    <Button variant="outline-secondary" size="sm" onClick={this.fetchQueue} disabled={loading}>
                        Refresh
                    </Button>
                    <span className="text-muted small">
                        {scored} of {this.state.cves.length} CVEs scored. Risk = KEV +40, EPSS x30, CVSS x2, recent +10.
                    </span>
                </div>

                {error && <div className="alert alert-danger py-2">{error}</div>}

                {loading ? (
                    <p className="text-muted small">Loading priority queue...</p>
                ) : rows.length === 0 ? (
                    <p className="text-muted small">
                        No CVEs match these filters. If nothing is scored yet, run
                        {' '}<code>python manage.py enrich_risk_scores --force</code> in the watcher container, then Refresh.
                    </p>
                ) : (
                    <div style={{ maxHeight: 320, overflowY: 'auto' }}>
                        <table className="table table-sm table-striped mb-0">
                            <thead>
                                <tr>
                                    <th>Priority</th>
                                    <th>Risk Score</th>
                                    <th>CVE ID</th>
                                    <th>EPSS</th>
                                    <th>KEV</th>
                                    <th>CVSS</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows.map(cve => (
                                    <tr key={cve.id || cve.cve_id}>
                                        <td>{this.renderPriorityBadge(cve.priority)}</td>
                                        <td><strong>{cve.risk_score != null ? cve.risk_score : 'Not scored yet'}</strong></td>
                                        <td>
                                            <a href={getCveUrl(cve.cve_id)} target="_blank" rel="noopener noreferrer"
                                                className="fw-semibold text-decoration-none">{cve.cve_id}</a>
                                        </td>
                                        <td>{cve.epss_score != null ? `${(cve.epss_score * 100).toFixed(1)}%` : '-'}</td>
                                        <td>{cve.is_kev ? <span className="badge bg-danger">EXPLOITED — KEV</span> : <span className="text-muted">-</span>}</td>
                                        <td>{cve.cvss_score != null ? cve.cvss_score : '-'}</td>
                                        <td style={{ maxWidth: 320, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
                                            title={cve.description || ''}>{cve.description || '-'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        );
    }
}

export default PriorityQueue;
