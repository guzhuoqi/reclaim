#!/usr/bin/env python3
import argparse
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def load_providers(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def iter_request_data(doc: Dict[str, Any]):
    providers = doc.get('providers') or {}
    for pid, prov in providers.items():
        pc = prov.get('providerConfig') or {}
        inner = pc.get('providerConfig') or {}
        rds = inner.get('requestData') or []
        for idx, rd in enumerate(rds):
            if not isinstance(rd, dict):
                continue
            url = rd.get('url') or ''
            yield pid, idx, url, rd


def build_matchers(response_matches: List[Dict[str, Any]]):
    matchers: List[Tuple[str, Any, bool]] = []
    for m in response_matches or []:
        mtype = (m.get('type') or 'regex').lower()
        val = m.get('value') or ''
        inv = bool(m.get('invert', False))
        if not val:
            continue
        if mtype == 'regex':
            try:
                rx = re.compile(val, re.S)
            except re.error:
                rx = None
            matchers.append(('regex', rx, inv))
        elif mtype == 'contains':
            matchers.append(('contains', val, inv))
    return matchers


def evaluate_matchers(body: str, matchers: List[Tuple[str, Any, bool]]) -> Tuple[bool, List[Tuple[str, bool]]]:
    results = []
    ok_all = True
    for mtype, val, inv in matchers:
        matched = False
        if mtype == 'regex' and val is not None:
            matched = bool(val.search(body))
        elif mtype == 'contains' and isinstance(val, str):
            matched = val in body
        if inv:
            matched = not matched
        results.append((mtype, matched))
        ok_all = ok_all and matched
    return ok_all, results


def try_load_flows_with_mitmproxy(flows_path: str) -> Dict[str, str]:
    try:
        from mitmproxy.io import FlowReader  # type: ignore
    except Exception:
        return {}

    url_to_body: Dict[str, str] = {}
    try:
        with open(flows_path, 'rb') as fp:
            fr = FlowReader(fp)
            for flow in fr.stream():
                try:
                    req_url = getattr(flow.request, 'url', '')
                    if not req_url:
                        continue
                    resp = getattr(flow, 'response', None)
                    if not resp:
                        continue
                    body_text = None
                    # mitmproxy v8+
                    get_text = getattr(resp, 'get_text', None)
                    if callable(get_text):
                        try:
                            body_text = resp.get_text(strict=False)
                        except Exception:
                            body_text = None
                    if body_text is None:
                        content = getattr(resp, 'content', None)
                        if isinstance(content, (bytes, bytearray)):
                            try:
                                body_text = content.decode('utf-8', errors='ignore')
                            except Exception:
                                body_text = ''
                    if body_text is None:
                        body_text = ''
                    url_to_body[req_url] = body_text
                except Exception:
                    continue
    except Exception:
        return {}
    return url_to_body


def main():
    ap = argparse.ArgumentParser(description='Validate responseMatches against responses in a mitmproxy .mitm dump')
    ap.add_argument('--flows', required=True, help='Path to mitmproxy flow dump (.mitm)')
    ap.add_argument('--providers', required=True, help='Path to providers JSON (reclaim_providers_*.json)')
    ap.add_argument('--filter-url', default='', help='Only validate requestData whose url contains this substring')
    args = ap.parse_args()

    providers = load_providers(args.providers)
    url_to_body = try_load_flows_with_mitmproxy(args.flows)
    if not url_to_body:
        print('WARN: mitmproxy 未可用或解析失败，无法精确匹配到应答正文。')
        print('      建议安装 mitmproxy 后重试: pip install mitmproxy')

    total = 0
    passed = 0
    failed = 0

    for pid, idx, url, rd in iter_request_data(providers):
        if args.filter_url and args.filter_url not in url:
            continue
        rms = rd.get('responseMatches') or []
        matchers = build_matchers(rms)
        if not matchers:
            continue
        total += 1

        # 找到对应应答正文（精确等于优先；其次 startswith；否则同主机最接近）
        body = ''
        if url_to_body:
            if url in url_to_body:
                body = url_to_body[url]
            else:
                # 退化：寻找以该URL开头的
                cand = [k for k in url_to_body.keys() if k.startswith(url.split('?')[0])]
                if cand:
                    body = url_to_body[cand[0]]

        ok, details = evaluate_matchers(body, matchers) if body else (False, [('no-body', False)])

        tag = 'PASS' if ok else 'FAIL'
        if ok:
            passed += 1
        else:
            failed += 1

        print(f'[{tag}] provider={pid} rd_index={idx}')
        print(f'  url: {url}')
        if not body:
            print('  body: <missing> (flow未解析到或无匹配应答)')
        for i, (mtype, mres) in enumerate(details, start=1):
            print(f'   - match[{i}]: type={mtype} -> {mres}')

    print('-' * 60)
    print(f'Summary: total={total}, passed={passed}, failed={failed}')
    if total == 0:
        print('Note: 没有匹配到需要校验的 requestData（请检查 --filter-url 或 providers 内容）。')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

