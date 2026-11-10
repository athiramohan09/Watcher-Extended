"""Manual feed test - FIX for 'no output, have to wait 30 minutes'.

Run inside the watcher container (no waiting for the scheduler):
    docker compose exec watcher python manage.py test_feeds

It runs the three CyberWatch fetchers immediately and prints what
actually landed in the database, plus which source is dead. If the
UI is empty after this, the problem is the frontend/API, not the feeds.
"""
import logging
from django.core.management.base import BaseCommand

from cyber_watch.core import fetch_latest_cves, fetch_ransomware_data, fetch_ransomlook_data
from cyber_watch.models import CVEAlert, RansomwareGroup, RansomwareVictim, WatchRuleHit

logger = logging.getLogger('watcher.cyber_watch')


class Command(BaseCommand):
    help = 'Run CyberWatch feeds immediately and report counts (no 30-min wait).'

    def handle(self, *args, **options):
        before = {
            'cves': CVEAlert.objects.count(),
            'groups': RansomwareGroup.objects.count(),
            'victims': RansomwareVictim.objects.count(),
            'hits': WatchRuleHit.objects.count(),
        }
        self.stdout.write(f"Before: {before}")

        self.stdout.write("Fetching CVEs from cve.circl.lu ...")
        fetch_latest_cves()
        self.stdout.write("Fetching ransomware.live (expected to warn: API dead) ...")
        fetch_ransomware_data()
        self.stdout.write("Fetching ransomlook (working source) ...")
        fetch_ransomlook_data()

        after = {
            'cves': CVEAlert.objects.count(),
            'groups': RansomwareGroup.objects.count(),
            'victims': RansomwareVictim.objects.count(),
            'hits': WatchRuleHit.objects.count(),
        }
        self.stdout.write(f"After:  {after}")
        self.stdout.write(
            "Added:  " + ", ".join(f"{k} +{after[k] - before[k]}" for k in before)
        )
        self.stdout.write(
            "Next: refresh Cyber Watch in the UI. If counts rose here but the "
            "UI is still empty, the bug is in the frontend/API, not the feeds."
        )
