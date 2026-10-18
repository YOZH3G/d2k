#!/usr/bin/env python3
"""Gate main documents and recorded resource regressions, not all site functions.

No retries or merging attempts: apply separately to each control directory.
A failure is an application/control failure, not automatically proof of DPI.
"""
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit, urldefrag


def required(page, request):
    host = urlsplit(page['url']).hostname
    asset = urlsplit(request['url'])
    kind = request.get('type')
    if host == 'rutracker.org':
        return asset.hostname == 'static.rutracker.cc' and kind in ('Stylesheet', 'Script')
    if host == 'www.fast-torrent.ru':
        return asset.hostname == 'media5.cdnbase.com' and kind in ('Stylesheet', 'Script')
    if host == 'enimerosi.com':
        return asset.hostname == 'cdnb.enimerosi.com' and kind == 'Image'
    return False


def complete(request):
    return request.get('finished') and 200 <= request.get('status', 0) < 300


def check(page):
    errors = []
    dom = page.get('dom') or {}
    if not dom.get('text') or dom.get('url', '').startswith('chrome-error:'):
        errors.append('страница пуста, ошибочна или DOM не измерен')
    requests = page.get('requests', [])
    final = urldefrag(dom.get('url', ''))[0]
    docs = [q for q in requests if q.get('type') == 'Document' and
            urldefrag(q['url'])[0] == final]
    if not any(complete(q) for q in docs):
        errors.append('основной документ не завершён успешным ответом')
    assets = [q for q in requests if required(page, q)]
    if urlsplit(page['url']).hostname in ('rutracker.org', 'www.fast-torrent.ru', 'enimerosi.com') and not assets:
        errors.append('контроль обязательных ресурсов не состоялся')
    # Only requested resources are judged. Offscreen lazy images listed by DOM
    # but never requested are not evidence of a truncated transfer.
    styles = set(dom.get('styles', []))
    for q in requests:
        if (required(page, q) or q['url'] in styles) and not complete(q):
            errors.append('ресурс не загружен: ' + q['url'] +
                          ' (' + str(q.get('error', q.get('status', 'pending'))) + ')')
    return errors


def main():
    root = Path(sys.argv[1])
    sites = [int(x) for x in sys.argv[2:]] or list(range(1, 20))
    failed = 0
    for i in sites:
        p = root / ('network-' + str(i)) / '1.json'
        try:
            page = json.loads(p.read_text())
            errors = check(page)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors = ['наблюдение отсутствует/некорректно: ' + str(exc)]
        if errors:
            failed += 1
            for error in errors:
                print(str(i) + ' FAIL ' + error)
        else:
            print(str(i) + ' PASS основной документ и проверяемые ресурсы')
    print('RESOURCE_GATE failed=' + str(failed) + ' checked=' + str(len(sites)))
    return int(failed != 0)


if __name__ == '__main__':
    sys.exit(main())
