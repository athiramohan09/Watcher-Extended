"""Daily Threat Report download API - Cyber Watch.

Lists the PDFs already generated in <BASE_DIR>/reports by
generate_daily_threat_report() (scheduled daily at 08:00, or on demand
via generate_daily_report), serves one PDF for download, and can
generate a fresh report on demand from the UI.

Security: only files named cyber_watch_daily_threat_report_*.pdf
inside the reports directory are ever listed or served. Any other
name, any '/' or '..' in the name, or any path escaping that
directory is rejected with 404. No other file on disk is reachable
through these endpoints.
"""
import os
import re
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.http import FileResponse, Http404
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

_REPORT_RE = re.compile(r"^cyber_watch_daily_threat_report_[A-Za-z0-9_.\-]+\.pdf$")


def _reports_dir():
    return os.path.join(settings.BASE_DIR, "reports")


def _safe_report_path(filename):
    if not filename or not _REPORT_RE.match(filename):
        raise Http404("Report not found")
    reports_dir = os.path.realpath(_reports_dir())
    path = os.path.realpath(os.path.join(reports_dir, filename))
    if os.path.dirname(path) != reports_dir or not os.path.isfile(path):
        raise Http404("Report not found")
    return path


class DailyReportListView(APIView):
    """GET /api/cyber_watch/daily-reports/ -> newest-first list of PDFs."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        reports_dir = _reports_dir()
        reports = []
        if os.path.isdir(reports_dir):
            for name in os.listdir(reports_dir):
                if not _REPORT_RE.match(name):
                    continue
                path = os.path.join(reports_dir, name)
                if not os.path.isfile(path):
                    continue
                mtime = os.path.getmtime(path)
                reports.append({
                    "filename": name,
                    "size": os.path.getsize(path),
                    "created_at": datetime.fromtimestamp(mtime, tz=dt_timezone.utc).isoformat(),
                    "download_url": f"/api/cyber_watch/daily-reports/download/{name}/",
                })
        reports.sort(key=lambda r: r["created_at"], reverse=True)
        return Response(reports)


class DailyReportDownloadView(APIView):
    """GET /api/cyber_watch/daily-reports/download/<filename>/ -> PDF file."""
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, filename):
        path = _safe_report_path(filename)
        return FileResponse(
            open(path, "rb"),
            content_type="application/pdf",
            as_attachment=True,
            filename=os.path.basename(path),
        )


class DailyReportGenerateView(APIView):
    """POST /api/cyber_watch/daily-reports/generate/ -> new PDF, last 24h."""
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        from .reports import generate_daily_threat_report

        try:
            result = generate_daily_threat_report(period_hours=24)
        except Exception as exc:
            return Response({"detail": f"Failed to generate daily threat report: {exc}"}, status=500)
        return Response({
            "pdf_filename": result["pdf_filename"],
            "counts": result["counts"],
            "top_5_groups": result["top_5_groups"],
            "email_status": result["email_status"],
            "download_url": f"/api/cyber_watch/daily-reports/download/{result['pdf_filename']}/",
        })
