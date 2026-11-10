"""Daily Threat Report generation command - for professor demo and on-demand reporting.

Usage inside the watcher container:
    docker compose exec watcher python manage.py generate_daily_report

Generates an executive PDF report covering the last 24 hours of Cyber Watch threat
intelligence data (new CVEs, new ransomware victims, new groups, and watch rule hits),
embeds charts and tables, saves the PDF, and attempts to send it via SMTP if configured.
"""
import os
import logging
from django.core.management.base import BaseCommand
from django.conf import settings
from cyber_watch.reports import generate_daily_threat_report

logger = logging.getLogger('watcher.cyber_watch')


class Command(BaseCommand):
    help = 'Generate the scheduled Cyber Watch Daily Threat Report immediately for the last 24 hours.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Reporting period in hours (default: 24).'
        )
        parser.add_argument(
            '--output-dir',
            type=str,
            default=None,
            help='Directory to store the generated PDF report.'
        )

    def handle(self, *args, **options):
        hours = options.get('hours', 24)
        output_dir = options.get('output_dir')

        self.stdout.write(self.style.NOTICE("=" * 70))
        self.stdout.write(self.style.NOTICE(f"Generating Cyber Watch Daily Threat Report (Last {hours} Hours)..."))
        self.stdout.write(self.style.NOTICE("=" * 70))

        try:
            result = generate_daily_threat_report(period_hours=hours, output_dir=output_dir)
        except Exception as exc:
            self.stderr.write(self.style.ERROR(f"Failed to generate daily threat report: {exc}"))
            logger.exception("Failed to generate daily threat report")
            return

        counts = result['counts']
        pdf_path = result['pdf_path']
        email_status = result['email_status']

        # Determine host path if mounted under /app/Watcher
        host_path = pdf_path
        if pdf_path.startswith('/app/Watcher'):
            rel_path = os.path.relpath(pdf_path, '/app/Watcher')
            host_path = os.path.join(r"D:\Users\Athira Mohandas\Desktop\Threat_intelligence\Watcher\Watcher\Watcher", rel_path)

        self.stdout.write(self.style.SUCCESS("\nReport generated successfully!"))
        self.stdout.write(f"Period Start:   {result['start_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        self.stdout.write(f"Period End:     {result['end_time'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
        self.stdout.write("-" * 70)
        self.stdout.write(self.style.SUCCESS("Summary Counts (Last 24 Hours):"))
        self.stdout.write(f"  * New CVEs:               {counts['cves']}")
        self.stdout.write(f"  * New Ransomware Victims: {counts['victims']}")
        self.stdout.write(f"  * New Ransomware Groups:  {counts['groups']}")
        self.stdout.write(f"  * Watch Rule Hits:        {counts['hits']}")
        self.stdout.write("-" * 70)

        if counts['hits'] == 0:
            self.stdout.write("Watch Rule Hits: No new hits in the last 24 hours")
        else:
            self.stdout.write(f"Watch Rule Hits: {counts['hits']} active hit(s) matched")

        if result['top_5_groups']:
            self.stdout.write("\nTop Ransomware Groups (Last 24 Hours):")
            for grp, cnt in result['top_5_groups']:
                self.stdout.write(f"  - {grp}: {cnt} victim(s)")

        self.stdout.write("-" * 70)
        self.stdout.write(self.style.SUCCESS(f"Saved PDF Path (Container): {pdf_path}"))
        self.stdout.write(self.style.SUCCESS(f"Saved PDF Path (Host PC):   {host_path}"))
        self.stdout.write(f"Email Status: {email_status}")
        self.stdout.write("=" * 70 + "\n")
