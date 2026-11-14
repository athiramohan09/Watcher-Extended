"""Enrich stored CVEs with AI risk scores - EPSS + CISA KEV.

Run inside the watcher container:
    docker compose exec watcher python manage.py enrich_risk_scores
    docker compose exec watcher python manage.py enrich_risk_scores --force
    docker compose exec watcher python manage.py enrich_risk_scores --limit 50

Without --force it only scores CVEs that have never been scored
(risk_score is NULL). With --force it re-scores everything, which is
what you want after the KEV list or EPSS values have moved on.

Risk formula (see cyber_watch/core.py: calculate_risk_score):
    KEV +40, EPSS * 30, (CVSS/10) * 20, published in last 30 days +10,
    capped 0-100. P1 >= 80, P2 60-79, P3 40-59, P4 < 40.
EPSS is FIRST's pre-trained machine-learning model, not a model
trained on the user's local CVEs. If EPSS or KEV is unreachable the
command warns and scores with what it has - it does not crash.
"""
import logging

from django.core.management.base import BaseCommand

from cyber_watch.core import enrich_cve_risk_scores

logger = logging.getLogger('watcher.cyber_watch')


class Command(BaseCommand):
    help = 'Score stored CVEs by exploit risk (EPSS + CISA KEV) and rank them Patch First.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit', type=int, default=None,
            help='Enrich at most this many CVEs, newest first (default: all).',
        )
        parser.add_argument(
            '--force', action='store_true',
            help='Re-score every CVE, even ones already scored.',
        )

    def handle(self, *args, **options):
        result = enrich_cve_risk_scores(limit=options.get('limit'), force=options.get('force'))
        self.stdout.write(f"Enriched: {result['enriched']} CVEs")
        self.stdout.write(f"On CISA KEV: {result['kev']} CVEs")
        if result['top_5']:
            self.stdout.write("Top 5 by risk score:")
            for item in result['top_5']:
                kev = 'KEV' if item['is_kev'] else '    '
                epss = f"{item['epss_score']:.2f}" if item['epss_score'] is not None else '-'
                self.stdout.write(
                    f"  {item['priority']}  risk {item['risk_score']:>5}  "
                    f"{item['cve_id']}  EPSS {epss}  CVSS {item['cvss_score']}  [{kev}]"
                )
        else:
            self.stdout.write("Top 5 by risk score: none scored yet.")
        self.stdout.write(
            "Next: refresh Cyber Watch in the UI (Ctrl+F5) - the Patch First "
            "card at the top shows the same ranking."
        )
