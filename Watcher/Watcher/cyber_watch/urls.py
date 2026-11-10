from django.urls import path
from rest_framework import routers
from .api import CVEAlertViewSet, RansomwareGroupViewSet, RansomwareVictimViewSet, WatchRuleViewSet, WatchRuleHitViewSet
from .core import start_scheduler
from .views import DailyReportDownloadView, DailyReportGenerateView, DailyReportListView

router = routers.DefaultRouter()
router.register('api/cyber_watch/cves', CVEAlertViewSet, 'cve-alerts')
router.register('api/cyber_watch/ransomware/groups', RansomwareGroupViewSet, 'ransomware-groups')
router.register('api/cyber_watch/ransomware/victims', RansomwareVictimViewSet, 'ransomware-victims')
router.register('api/cyber_watch/watch-rules', WatchRuleViewSet, 'watch-rules')
router.register('api/cyber_watch/watch-rule-hits', WatchRuleHitViewSet, 'watch-rule-hits')

urlpatterns = [
    path('api/cyber_watch/daily-reports/', DailyReportListView.as_view(), name='daily-reports'),
    path('api/cyber_watch/daily-reports/generate/', DailyReportGenerateView.as_view(), name='daily-report-generate'),
    path('api/cyber_watch/daily-reports/download/<str:filename>/', DailyReportDownloadView.as_view(), name='daily-report-download'),
] + router.urls

start_scheduler()
