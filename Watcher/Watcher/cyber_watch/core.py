# coding=utf-8
import logging
import requests
from datetime import timedelta
from django.utils import timezone
from django.db import close_old_connections
from django.utils.dateparse import parse_datetime
from connectors.core import get_cyberwatch_cve_config, get_ransomware_live_config, get_ransomlook_config
from apscheduler.schedulers.background import BackgroundScheduler
import tzlocal

from .models import CVEAlert, RansomwareGroup, RansomwareVictim, WatchRule, WatchRuleHit, Subscriber
from common.core import send_app_specific_notifications
from django.db.models import Q
from .reports import generate_daily_threat_report

# Configure logger
logger = logging.getLogger('watcher.cyber_watch')

# ---------------------------------------------------------------------------
# FIX (2026-10-26, sher/Watcher-personalised):
# Upstream feeds changed shape in 2026 and the old code failed silently:
#  * ransomware.live v2/* now returns 404 / HTML, not JSON -> resp.json()
#    raised and the whole ransomware section stayed empty with only a
#    log line nobody sees in the UI.
#  * ransomlook /api/recent items use post_title/group_name, not
#    name/group, so the old victim loop skipped every single item.
#  * circl /api/last now mixes OSV/PYSEC items and CVE-JSON items
#    (cveMetadata.cveId + containers.cna.descriptions). The old
#    description fallback missed several of those.
# _get_json() makes a feed failure explicit (ok/data/error) instead of
# crashing, and the fetchers below fall back to the source that works.
# ---------------------------------------------------------------------------

def _get_json(url, timeout=20):
    """GET url and return (data, error). error is None on success.

    A 404, an HTML page (dead API returning its website) or bad JSON
    all return an error string instead of raising - callers can then
    log it, report source health, and continue with the next source.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        return None, f"{type(exc).__name__}: {exc}"
    content_type = resp.headers.get('Content-Type', '')
    if 'json' not in content_type and resp.text.lstrip().startswith('<'):
        return None, f"non-JSON response (HTML, HTTP {resp.status_code}) - API endpoint may be dead"
    try:
        return resp.json(), None
    except ValueError as exc:
        return None, f"invalid JSON: {exc}"


def _extract_cve_description(item):
    """Best-effort description for both old CIRCL items and CVE-JSON items."""
    cna = (((item.get('containers') or {}).get('cna') or {}).get('descriptions') or [])
    cna_text = cna[0].get('value', '') if cna else ''
    adp = (((item.get('containers') or {}).get('adp') or [{}])[0].get('descriptions') or [])
    adp_text = adp[0].get('value', '') if adp else ''
    top_desc = ''
    descs = item.get('descriptions') or []
    if descs and isinstance(descs[0], dict):
        top_desc = descs[0].get('value', '')
    affected = item.get('affected') or []
    affected_text = ''
    if affected and isinstance(affected[0], dict):
        affected_text = affected[0].get('product', '') or ''
    return (
        item.get('title', '')
        or item.get('summary', '')
        or item.get('details', '')
        or top_desc
        or cna_text
        or adp_text
        or (f"Affects {affected_text}" if affected_text else '')
    )



def start_scheduler():
    """
    Launch multiple planning tasks in background:
        - Fetch latest CVEs every 30 minutes.
        - Fetch ransomware data every 30 minutes.
        - Fetch RansomLook data every 30 minutes.
        - Generate daily threat report daily at 08:00.
    """
    scheduler = BackgroundScheduler(timezone=str(tzlocal.get_localzone()))
    scheduler.add_job(fetch_latest_cves, 'interval', minutes=30, id='fetch_latest_cves',
        max_instances=1,
        replace_existing=True)
    scheduler.add_job(fetch_ransomware_data, 'interval', minutes=30, id='fetch_ransomware_data',
        max_instances=1,
        replace_existing=True)
    scheduler.add_job(fetch_ransomlook_data, 'interval', minutes=30, id='fetch_ransomlook_data',
        max_instances=1,
        replace_existing=True)
    scheduler.add_job(generate_daily_threat_report, 'cron', hour=8, minute=0, id='daily_threat_report',
        max_instances=1,
        replace_existing=True)
    scheduler.start()


def _match_keyword_against_fields(keyword, exceptions, fields):
    """
    Check if a keyword matches any field value, considering exceptions.

    :param keyword: Keyword to search for (case-insensitive).
    :param exceptions: List of exception keywords that cancel a match.
    :param fields: Dictionary of {field_name: field_value} to search in.
    :return: True if keyword matches and no exception matches.
    :rtype: bool
    """
    for exc in exceptions:
        for val in fields.values():
            if val and exc.lower() in val.lower():
                return False

    for val in fields.values():
        if val and keyword.lower() in val.lower():
            return True

    return False


def _check_watch_rules_for_cve(cve):
    """
    Check a CVE alert against active WatchRules and record matching hits.

    :param cve: CVEAlert object to check.
    :return: None
    """
    try:
        rules = WatchRule.objects.filter(is_active=True, scope__in=['cve', 'both'])
        
        fields = {
            'cve_id': cve.cve_id,
            'description': cve.description,
            'severity': cve.severity,
        }

        for rule in rules:
            for keyword in rule.keywords:
                if not keyword:
                    continue

                if _match_keyword_against_fields(keyword, rule.exceptions, fields):
                    hit, created = WatchRuleHit.objects.get_or_create(
                        rule=rule,
                        hit_type='cve',
                        object_id=cve.cve_id,
                        matched_keyword=keyword,
                        defaults={
                            'hit_display': f"{cve.cve_id} - {cve.description[:300]}",
                            'hit_at': timezone.now(),
                        }
                    )
                    if created:
                        try:
                            send_cyber_watch_notifications({
                                'notification_type': 'cve_hit',
                                'rule_name': rule.name,
                                'cve_id': cve.cve_id,
                                'keyword': keyword,
                                'severity': cve.severity or 'N/A',
                            })
                        except Exception as e:
                            logger.error(f"CVE hit notification error: {e}")
    except Exception as e:
        logger.error(f"Error checking watch rules for CVE: {e}")


def _check_watch_rules_for_victim(victim):
    """
    Check a ransomware victim against active WatchRules and record matching hits.

    :param victim: RansomwareVictim object to check.
    :return: None
    """
    try:
        rules = WatchRule.objects.filter(is_active=True, scope__in=['ransomware', 'both'])

        fields = {
            'victim_name': victim.victim_name,
            'country': victim.country,
            'sector': victim.sector,
            'group_name': victim.group.name if victim.group_id else '',
        }

        obj_id = (f"{victim.group.name}::{victim.victim_name}" 
                  if victim.group_id else victim.victim_name)

        for rule in rules:
            for keyword in rule.keywords:
                if not keyword:
                    continue

                if _match_keyword_against_fields(keyword, rule.exceptions, fields):
                    hit, created = WatchRuleHit.objects.get_or_create(
                        rule=rule,
                        hit_type='ransomware_victim',
                        object_id=obj_id[:500],
                        matched_keyword=keyword,
                        defaults={
                            'hit_display': f"{victim.victim_name} ({fields['group_name']}) - {victim.country}",
                            'hit_at': timezone.now(),
                        }
                    )
                    if created:
                        try:
                            send_cyber_watch_notifications({
                                'notification_type': 'victim_hit',
                                'rule_name': rule.name,
                                'victim_name': victim.victim_name,
                                'group_name': fields['group_name'],
                                'keyword': keyword,
                                'sector': victim.sector or 'N/A',
                                'country': victim.country or 'N/A',
                            })
                        except Exception as e:
                            logger.error(f"Victim hit notification error: {e}")
    except Exception as e:
        logger.error(f"Error checking watch rules for ransomware victim: {e}")


def fetch_latest_cves():
    """
    Fetch latest CVEs from cve.circl.lu API and store new ones in database.
    Automatically matches against active WatchRules and records hits.

    :return: None
    """
    try:
        close_old_connections()
        logger.info("CRON TASK : Fetch latest CVEs from cve.circl.lu")

        cve_url = get_cyberwatch_cve_config()['cve_api_url']
        data, err = _get_json(cve_url, timeout=15)
        if err:
            logger.error(f"CVE API unavailable at {cve_url}: {err} - CVE list will not update this run")
            return
        if isinstance(data, dict):
            # Some CIRCL responses wrap the list, e.g. {"results": [...]}
            data = data.get('results') or data.get('data') or data.get('vulnerabilities') or []
        if not isinstance(data, list):
            logger.error(f"CVE API returned unexpected shape: {type(data).__name__}")
            return

        def normalize_severity(raw, fallback=''):
            if isinstance(raw, str):
                return raw.upper()
            if isinstance(raw, list):
                for value in raw:
                    if isinstance(value, str) and value.strip():
                        return value.upper()
                    if isinstance(value, dict):
                        candidate = (
                            value.get('severity')
                            or value.get('baseSeverity')
                            or value.get('score')
                            or value.get('value')
                            or ''
                        )
                        if isinstance(candidate, str) and candidate.strip():
                            return candidate.upper()
                return fallback.upper() if isinstance(fallback, str) else ''
            if isinstance(raw, dict):
                candidate = (
                    raw.get('severity')
                    or raw.get('baseSeverity')
                    or raw.get('score')
                    or raw.get('value')
                    or ''
                )
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.upper()
                return fallback.upper() if isinstance(fallback, str) else ''
            return fallback.upper() if isinstance(fallback, str) else ''

        def normalize_severity_label(raw):
            value = normalize_severity(raw)
            if value.startswith('CVSS:'):
                return ''
            if value in {'MODERATE'}:
                return 'MEDIUM'
            return value

        def extract_cvss_score(item):
            raw = item.get('cvss', None)
            if isinstance(raw, (int, float)):
                return float(raw)
            if isinstance(raw, str):
                try:
                    return float(raw)
                except Exception:
                    pass

            for sev in item.get('severity', []) or []:
                if not isinstance(sev, dict):
                    continue
                score = sev.get('score')
                if isinstance(score, (int, float)):
                    return float(score)
                if isinstance(score, str):
                    try:
                        return float(score)
                    except Exception:
                        continue
            return None

        def extract_cve_id(item):
            raw_id = item.get('id', '') or item.get('cveMetadata', {}).get('cveId', '')
            if isinstance(raw_id, str) and raw_id.upper().startswith('CVE-'):
                return raw_id
            aliases = item.get('aliases', []) or []
            for alias in aliases:
                if isinstance(alias, str) and alias.upper().startswith('CVE-'):
                    return alias
            return raw_id
        
        new_count = 0
        skipped_count = 0
        for item in data:
            if not isinstance(item, dict):
                skipped_count += 1
                continue
            cve_id = extract_cve_id(item)
            if not cve_id:
                skipped_count += 1
                continue

            description = _extract_cve_description(item)

            published_raw = (
                item.get('Published')
                or item.get('published')
                or item.get('cveMetadata', {}).get('datePublished')
                or ((item.get('database_specific') or {}).get('nvd_published_at'))
            )
            published = None
            if published_raw:
                try:
                    dt = parse_datetime(str(published_raw))
                    if dt is not None:
                        # Strip timezone info to make it naive
                        published = dt.replace(tzinfo=None)
                except Exception:
                    published = None

            severity = normalize_severity_label(
                item.get('severity', ''),
            ) or normalize_severity_label((item.get('database_specific') or {}).get('severity', ''))

            defaults = {
                'description': description,
                'cvss_score': extract_cvss_score(item),
                'severity': severity,
                'published': published,
                'references': item.get('references', []),
                'fetched_at': timezone.now(),
            }

            obj, created = CVEAlert.objects.update_or_create(cve_id=cve_id, defaults=defaults)
            if created:
                new_count += 1
                try:
                    send_cyber_watch_notifications({
                        'notification_type': 'new_cve',
                        'cve_id': obj.cve_id,
                        'severity': obj.severity or 'N/A',
                        'cvss_score': obj.cvss_score or 'N/A',
                        'description': (obj.description or '')[:300],
                    })
                except Exception as e:
                    logger.error(f"New CVE notification error: {e}")

            # Check if this CVE matches any active watch rules
            _check_watch_rules_for_cve(obj)

        logger.info(f"CVE fetch complete - {new_count} new CVEs added, {skipped_count} items skipped (no usable CVE id), {len(data)} total in feed")

    except requests.exceptions.RequestException as e:
        logger.error(f"CVE API request error: {e}")
    except Exception as e:
        logger.error(f"CVE fetch error: {e}")


def fetch_ransomware_data():
    """
    Fetch ransomware groups and recent victims from ransomware.live API.
    Automatically matches against active WatchRules and records hits.

    :return: None
    """
    close_old_connections()
    logger.info("CRON TASK : Fetch ransomware groups and victims from ransomware.live")
    
    try:
        groups_url = get_ransomware_live_config()['groups_url']
        groups_data, groups_err = _get_json(groups_url, timeout=20)
        if groups_err:
            # FIX: ransomware.live v2 API is dead (404/HTML as of Oct 2026).
            # Do NOT crash the job - ransomlook (below) still populates
            # RansomwareGroup/RansomwareVictim, so the page is not empty.
            logger.warning(f"Ransomware.live groups unavailable at {groups_url}: {groups_err} - skipping, ransomlook remains the working source")
            groups_data = []
        group_count = 0
        for g in groups_data:
            name = g.get('name', '').strip()
            if not name:
                continue

            # Store or update ransomware group
            _, created = RansomwareGroup.objects.update_or_create(
                name=name,
                defaults={
                    'description': g.get('description') or '',
                    'source': 'ransomware.live',
                    'fetched_at': timezone.now(),
                }
            )
            if created:
                group_count += 1

        logger.info(f"Ransomware groups fetch complete - {group_count} new groups")

    except requests.exceptions.RequestException as e:
        logger.error(f"Ransomware groups API request error: {e}")
    except Exception as e:
        logger.error(f"Ransomware groups fetch error: {e}")

    try:
        victims_url = get_ransomware_live_config()['victims_url']
        victims_data, victims_err = _get_json(victims_url, timeout=20)
        if victims_err:
            logger.warning(f"Ransomware.live victims unavailable at {victims_url}: {victims_err} - skipping, ransomlook remains the working source")
            victims_data = []
        new_count = 0
        for v in victims_data:
            group_name = (v.get('group_name', '') or v.get('group', '')).strip()
            if not group_name:
                continue

            group, _ = RansomwareGroup.objects.get_or_create(
                name=group_name,
                defaults={'source': 'ransomware.live', 'fetched_at': timezone.now()}
            )

            victim_name = (v.get('victim', '') or v.get('post_title', '')).strip()
            if not victim_name:
                continue

            attacked_raw = v.get('published') or v.get('discovered')
            attacked_at = None
            if attacked_raw:
                try:
                    dt = parse_datetime(str(attacked_raw))
                    if dt is not None:
                        attacked_at = dt.replace(tzinfo=None)
                except Exception:
                    attacked_at = None

            victim, created = RansomwareVictim.objects.update_or_create(
                group=group,
                victim_name=victim_name,
                attacked_at=attacked_at,
                defaults={
                    'country': v.get('country') or '',
                    'sector': v.get('activity') or v.get('sector') or '',
                    'url': v.get('url', ''),
                    'fetched_at': timezone.now(),
                }
            )

            if created:
                new_count += 1
                
                _check_watch_rules_for_victim(victim)

                try:
                    send_cyber_watch_notifications({
                        'notification_type': 'new_victim',
                        'victim_name': victim.victim_name,
                        'group_name': group_name,
                        'country': victim.country or 'N/A',
                        'sector': victim.sector or 'N/A',
                    })
                except Exception as e:
                    logger.error(f"New victim notification error: {e}")

        logger.info(f"Ransomware victims fetch complete - {new_count} new victims")

    except requests.exceptions.RequestException as e:
        logger.error(f"Ransomware victims API request error: {e}")
    except Exception as e:
        logger.error(f"Ransomware victims fetch error: {e}")


def fetch_ransomlook_data():
    """
    Fetch ransomware data from RansomLook API.
    Includes groups, recent victims, and threat actors.
    Automatically matches against active WatchRules and records hits.

    :return: None
    """
    close_old_connections()
    logger.info("CRON TASK : Fetch ransomware data from ransomlook.io")

    try:
        resp = requests.get(get_ransomlook_config()['groups_url'], timeout=20)
        resp.raise_for_status()

        group_count = 0
        data = resp.json()

        if isinstance(data, dict):
            items = [{'name': k, **(v if isinstance(v, dict) else {})} for k, v in data.items()]
        else:
            items = data

        for g in items:
            # Handle both string items and dict items
            if isinstance(g, str):
                name = g.strip()
            else:
                name = (g.get('name') or '').strip()
            if not name:
                continue

            # Store or update ransomware group with RansomLook as source
            _, created = RansomwareGroup.objects.update_or_create(
                name=name,
                defaults={
                    'description': (g.get('description') or g.get('profile') or '') if isinstance(g, dict) else '',
                    'source': 'ransomlook.io',
                    'first_seen': (g.get('first_seen') or None) if isinstance(g, dict) else None,
                    'fetched_at': timezone.now(),
                }
            )
            if created:
                group_count += 1

        logger.info(f"RansomLook groups fetch complete - {group_count} new groups")

    except requests.exceptions.RequestException as e:
        logger.error(f"RansomLook groups API request error: {e}")
    except Exception as e:
        logger.error(f"RansomLook groups fetch error: {e}")

    try:
        recent_url = get_ransomlook_config()['recent_url']
        recent_data, recent_err = _get_json(recent_url, timeout=20)
        if recent_err:
            logger.error(f"RansomLook recent unavailable at {recent_url}: {recent_err}")
            recent_data = []
        victim_count = 0
        for v in recent_data:
            # FIX: ransomlook /api/recent actually returns
            #   post_title, group_name, discovered, link, description
            # not name/group/organization. The old mapping skipped
            # every victim, so the page stayed empty despite HTTP 200.
            group_name = (v.get('group_name', '') or v.get('group', '') or v.get('actor', '') or '').strip()
            if not group_name:
                continue

            group, _ = RansomwareGroup.objects.get_or_create(
                name=group_name,
                defaults={'source': 'ransomlook.io', 'fetched_at': timezone.now()}
            )

            victim_name = (v.get('post_title', '') or v.get('name', '') or v.get('organization', '') or '').strip()
            if not victim_name:
                continue

            attacked_raw = v.get('post_date') or v.get('discovered') or v.get('date_added')
            attacked_at = None
            if attacked_raw:
                try:
                    dt = parse_datetime(str(attacked_raw))
                    if dt is not None:
                        attacked_at = dt.replace(tzinfo=None)
                except Exception:
                    attacked_at = None

            victim, created = RansomwareVictim.objects.update_or_create(
                group=group,
                victim_name=victim_name,
                attacked_at=attacked_at,
                defaults={
                    'country': v.get('country') or '',
                    'sector': v.get('industry') or v.get('sector') or '',
                    'url': v.get('link') or v.get('url', ''),
                    'fetched_at': timezone.now(),
                }
            )

            if created:
                victim_count += 1

                _check_watch_rules_for_victim(victim)

                try:
                    send_cyber_watch_notifications({
                        'notification_type': 'new_victim',
                        'victim_name': victim.victim_name,
                        'group_name': group_name,
                        'country': victim.country or 'N/A',
                        'sector': victim.sector or 'N/A',
                    })
                except Exception as e:
                    logger.error(f"New victim notification error: {e}")

        logger.info(f"RansomLook victims fetch complete - {victim_count} new victims")

    except requests.exceptions.RequestException as e:
        logger.error(f"RansomLook victims API request error: {e}")
    except Exception as e:
        logger.error(f"RansomLook victims fetch error: {e}")

    try:
        resp = requests.get(get_ransomlook_config()['actors_url'], timeout=20)
        resp.raise_for_status()

        actor_count = 0
        for actor in resp.json():
            # RansomLook actors often map to groups
            actor_name = actor.get('name', '').strip()
            if not actor_name:
                continue

            # Store as a ransomware group if not already present
            _, created = RansomwareGroup.objects.get_or_create(
                name=actor_name,
                defaults={
                    'description': actor.get('description', f'Threat actor: {actor_name}'),
                    'source': 'ransomlook.io (actors)',
                    'fetched_at': timezone.now(),
                }
            )
            if created:
                actor_count += 1

        logger.info(f"RansomLook actors fetch complete - {actor_count} new actors")

    except requests.exceptions.RequestException as e:
        logger.error(f"RansomLook actors API request error: {e}")
    except Exception as e:
        logger.error(f"RansomLook actors fetch error: {e}")


def send_cyber_watch_notifications(content):
    """
    Send CyberWatch notifications to all enabled subscribers via Slack, Citadel, TheHive and/or Email.
    """
    notification_type = content.get('notification_type', '')

    # Filter subscribers by channel availability
    subscribers = Subscriber.objects.filter(
        Q(slack=True) | Q(citadel=True) | Q(thehive=True) | Q(email=True)
    )

    if not subscribers.exists():
        logger.warning(f"{timezone.now()} - No CyberWatch subscribers configured, no notification sent.")
        return

    # Filter by subscription preference
    if notification_type == 'new_cve':
        subscribers = subscribers.filter(notify_all_cves=True)
    elif notification_type == 'cve_hit':
        subscribers = subscribers.filter(notify_cve_hits=True)
    elif notification_type == 'new_victim':
        subscribers = subscribers.filter(notify_all_victims=True)
    elif notification_type == 'victim_hit':
        subscribers = subscribers.filter(notify_victim_hits=True)

    if not subscribers.exists():
        return

    send_app_specific_notifications('cyber_watch', content, subscribers)
