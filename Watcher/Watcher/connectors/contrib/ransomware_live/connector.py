import requests

DEFINITION = {
    'id': 'ransomware_live',
    'name': 'Ransomware.live',
    'logo': '💀',
    'category': 'Threat Intelligence',
    'description': 'Ransomware.live victim and group tracking API. NOTE (Oct 2026): the v2 API now returns 404/HTML, so Watcher treats it as degraded and uses RansomLook as the working ransomware source. See cyber_watch/core.py.',
    'readonly': False,
    'version': '1.0.0',
    'author': 'Thales CERT',
    'fields': [
        {'name': 'CYBER_WATCH_RANSOMWARE_GROUPS_URL',  'label': 'Groups URL',  'type': 'text', 'settings_key': 'CYBER_WATCH_RANSOMWARE_GROUPS_URL',  'required': True, 'default': 'https://api.ransomware.live/v2/groups'},
        {'name': 'CYBER_WATCH_RANSOMWARE_VICTIMS_URL', 'label': 'Victims URL', 'type': 'text', 'settings_key': 'CYBER_WATCH_RANSOMWARE_VICTIMS_URL', 'required': False, 'default': 'https://api.ransomware.live/v2/recentvictims'},
    ],
}


def health_check(plain):
    url = plain('CYBER_WATCH_RANSOMWARE_GROUPS_URL')
    if not url:
        return {'success': False, 'message': 'Ransomware.live URL not configured'}
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code} - ransomware.live API endpoint is dead/moved'}
        # FIX: /groups used to return 200 but with an HTML website, not JSON.
        # A plain 200 check therefore lied on the /connectors page.
        if 'json' not in resp.headers.get('Content-Type', '') and resp.text.lstrip().startswith('<'):
            return {'success': False, 'message': 'HTTP 200 but HTML, not JSON - ransomware.live API is no longer available'}
        resp.json()
        return {'success': True, 'message': f'Ransomware.live API reachable at {url}'}
    except Exception as exc:
        return {'success': False, 'message': str(exc)}
