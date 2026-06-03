#!/usr/bin/env python3
"""
Filters OpenGrep SAST results against dismissed findings (false positives
marked in the IDE extension). Used by the CI/CD pipeline to respect
false positives already reviewed by developers.
"""
import sys
import json
import os


def extract_rule_name(raw_id):
    """
    Extract the rule name from a check_id.
    The IDE extension stores IDs with the full extension path prefix:
      "Users.guilherme...rules.command-injection-eval"
    OpenGrep in CI produces IDs like:
      "rules.command-injection-eval"
    We normalize by extracting everything after the last 'rules.' prefix.
    """
    if '.rules.' in raw_id:
        return raw_id.split('.rules.')[-1]
    return raw_id.split('.')[-1]


def load_dismissed(dismissed_file):
    """Load dismissed findings and build a lookup set."""
    if not dismissed_file or not os.path.exists(dismissed_file):
        return set()

    try:
        with open(dismissed_file) as f:
            dismissed = json.load(f)
    except (json.JSONDecodeError, IOError):
        return set()

    keys = set()
    for d_item in dismissed:
        rule_name = extract_rule_name(d_item.get('id', ''))
        file_path = d_item.get('file', '')
        line = d_item.get('line', 0)
        # Match by rule + file + line (precise)
        keys.add((rule_name, file_path, line))
        # Match by rule + file only (line may shift between commits)
        keys.add((rule_name, file_path, 0))
    return keys


def main():
    if len(sys.argv) < 2:
        print("Usage: filter-dismissed.py <opengrep-results.json> [dismissed.json]")
        sys.exit(1)

    results_file = sys.argv[1]
    dismissed_file = sys.argv[2] if len(sys.argv) > 2 else None

    # Load OpenGrep results
    try:
        with open(results_file) as f:
            data = json.load(f)
        results = data.get('results', [])
    except (json.JSONDecodeError, IOError):
        sys.exit(0)
    finally:
        if os.path.exists(results_file):
            os.unlink(results_file)

    if not results:
        print("  No security findings detected.")
        sys.exit(0)

    # Filter out dismissed findings (false positives)
    dismissed_keys = load_dismissed(dismissed_file)
    if dismissed_keys:
        filtered = []
        for r in results:
            rule_name = extract_rule_name(r.get('check_id', ''))
            file_path = r.get('path', '')
            line = r.get('start', {}).get('line', 0)

            if (rule_name, file_path, line) in dismissed_keys:
                continue
            if (rule_name, file_path, 0) in dismissed_keys:
                continue
            filtered.append(r)
        results = filtered

    if not results:
        print("  All findings were marked as false positives (dismissed).")
        sys.exit(0)

    # Display results
    total = len(results)
    error_c = sum(1 for r in results if r.get('extra', {}).get('severity', '').upper() == 'ERROR')
    warn_c = sum(1 for r in results if r.get('extra', {}).get('severity', '').upper() == 'WARNING')
    info_c = total - error_c - warn_c

    print()
    print(f'  SAST SCAN FAILED - {total} vulnerability(ies) detected')
    print()
    parts = []
    if error_c:
        parts.append(f'{error_c} critical/high')
    if warn_c:
        parts.append(f'{warn_c} medium')
    if info_c:
        parts.append(f'{info_c} low/info')
    print(f'  {" | ".join(parts)}')
    print()

    sep = "-" * 66
    print(f'  {sep}')
    print(f'  {"Sev":<9} {"Rule":<30} {"File":<20} {"Line"}')
    print(f'  {sep}')

    for r in results:
        sev = r.get('extra', {}).get('severity', 'INFO').upper()
        check_id = r.get('check_id', '?')
        rule = check_id.split('.')[-1].replace('-', ' ').title()[:28]
        file_path = r.get('path', '?')
        if len(file_path) > 18:
            file_path = '...' + file_path[-15:]
        line = r.get('start', {}).get('line', '?')
        print(f'  {sev:<9} {rule:<30} {file_path:<20} L{line}')

    print(f'  {sep}')
    print()
    print('  To dismiss a finding as false positive, use the IDE extension')
    print('  and commit the updated .appsec-state/dismissed.json file.')
    print()

    # Fail if there are ERROR-level findings (critical/high)
    if error_c > 0:
        sys.exit(1)
    else:
        print('  Non-blocking findings detected. Review recommended.')
        sys.exit(0)


if __name__ == '__main__':
    main()
