#!/usr/bin/env python3
"""
rules_order_report.py - Debug utility for azionify-generated Terraform.

Reconstructs the execution order of `azion_edge_application_rule_engine` rules by
topologically sorting their rule->rule `depends_on` chain, and prints the sequence
with behavior/criteria annotations. It also flags order smells that are otherwise
very hard to spot in a large generated file - notably a forward-rewrite rule that
runs BEFORE its set_origin (the pattern that makes cloudlet forwards 404).

Why this exists: azionify does not emit the rule-engine `order` field, so the real
execution order is implicit in the `depends_on` chain, spread across tens of
thousands of lines. This makes the actual order impossible to read by eye.

Usage:
    python rules_order_report.py <azion.tf> [--phase request|response|default]
                                            [--grep TEXT] [--mermaid-forward]
"""
import argparse
import re
from collections import deque


RULE_RE = re.compile(r'resource "azion_edge_application_rule_engine" "([^"]+)"')


def parse_rules(text):
    """Parse every rule-engine block into a dict with name/phase/behaviors/criteria/deps."""
    lines = text.split('\n')
    rules = []
    i = 0
    while i < len(lines):
        m = RULE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = 0
        j = i
        while j < len(lines):
            depth += lines[j].count('{') - lines[j].count('}')
            if depth == 0 and j > i:
                break
            j += 1
        body = '\n'.join(lines[i:j + 1])

        phase_m = re.search(r'phase\s*=\s*"([^"]+)"', body)
        phase = phase_m.group(1) if phase_m else '?'

        # Behavior names are written as `name = "X"` (single space); the results
        # name uses aligned padding (`name        = "X"`), so it is not matched.
        behaviors = re.findall(r'\n\s+name = "([^"]+)"', body)

        # Criteria variables (what the rule reads to decide if it fires).
        criteria_vars = re.findall(r'variable\s*=\s*"([^"]+)"', body)

        # rule -> rule dependencies (ignore self and non-rule resources).
        deps = set(re.findall(r'azion_edge_application_rule_engine\.([A-Za-z0-9_]+)', body))
        deps.discard(name)

        rules.append({
            'name': name,
            'phase': phase,
            'behaviors': behaviors,
            'criteria': criteria_vars,
            'deps': deps,
            'pos': i + 1,  # 1-based line number in the file
        })
        i = j + 1
    return rules


def execution_order(rules):
    """Topologically sort rules by their rule->rule depends_on edges.

    Edge dep -> rule means dep must run before rule. Ties (several ready rules)
    are broken by original file position for stable, readable output.
    """
    by_name = {r['name']: r for r in rules}
    indeg = {r['name']: 0 for r in rules}
    adj = {r['name']: [] for r in rules}
    for r in rules:
        for d in r['deps']:
            if d in by_name:  # only edges to known rules
                adj[d].append(r['name'])
                indeg[r['name']] += 1

    # ready = in-degree 0, kept sorted by file position
    ready = sorted([n for n in indeg if indeg[n] == 0], key=lambda n: by_name[n]['pos'])
    order = []
    ready = deque(ready)
    while ready:
        # pick the ready node with smallest file position (stable)
        ready = deque(sorted(ready, key=lambda n: by_name[n]['pos']))
        n = ready.popleft()
        order.append(by_name[n])
        for nb in adj[n]:
            indeg[nb] -= 1
            if indeg[nb] == 0:
                ready.append(nb)

    cyclic = [by_name[n] for n in indeg if indeg[n] > 0]
    return order, cyclic


def tag(rule):
    """Short annotation of what the rule does / reads, focused on the forward flow."""
    b = set(rule['behaviors'])
    crit = ' '.join(rule['criteria'])
    parts = []
    if 'set_origin' in b:
        parts.append('set_origin')
    if 'rewrite_request' in b:
        parts.append('rewrite_request')
    if 'run_function' in b:
        parts.append('run_function')
    other = sorted(b - {'set_origin', 'rewrite_request', 'run_function'})
    if other:
        parts.append('+' + ','.join(other[:3]) + ('...' if len(other) > 3 else ''))
    reads = []
    if 'http_x_az_forward_rewrite_origin' in crit:
        reads.append('reads:origin-hdr')
    if 'http_x_az_forward_rewrite_uri' in crit:
        reads.append('reads:uri-hdr')
    return ' | '.join(parts + reads)


def is_fwd_setorigin(rule):
    return 'set_origin' in rule['behaviors'] and any('http_x_az_forward_rewrite_origin' in c for c in rule['criteria'])


def is_fwd_rewrite(rule):
    return 'rewrite_request' in rule['behaviors'] and any('http_x_az_forward_rewrite_uri' in c for c in rule['criteria'])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('tf_file', help='Path to an azionify-generated azion.tf')
    ap.add_argument('--phase', choices=['request', 'response', 'default'], help='Filter by phase')
    ap.add_argument('--grep', help='Only show rules whose name/tag contains TEXT')
    ap.add_argument('--mermaid-forward', action='store_true',
                    help='Emit a Mermaid graph scoped to the forward flow (function/set_origin/rewrite)')
    args = ap.parse_args()

    with open(args.tf_file, encoding='utf-8') as f:
        rules = parse_rules(f.read())

    order, cyclic = execution_order(rules)

    shown = order
    if args.phase:
        shown = [r for r in shown if r['phase'] == args.phase]
    if args.grep:
        g = args.grep.lower()
        shown = [r for r in shown if g in r['name'].lower() or g in tag(r).lower()]

    print(f"# Rule execution order (via depends_on)  -  {len(order)} rules total, showing {len(shown)}\n")
    print(f"{'seq':>4}  {'line':>6}  {'phase':<8}  {'rule':<48}  annotation")
    print('-' * 120)
    seq_of = {r['name']: k for k, r in enumerate(order)}
    for r in shown:
        print(f"{seq_of[r['name']]:>4}  {r['pos']:>6}  {r['phase']:<8}  {r['name'][:48]:<48}  {tag(r)}")

    if cyclic:
        print(f"\n[!] {len(cyclic)} rule(s) in a dependency cycle (order undefined): "
              + ', '.join(r['name'] for r in cyclic[:10]))

    # ---- Order smell: forward-rewrite running before a set_origin ----
    rewrites = [(seq_of[r['name']], r) for r in order if is_fwd_rewrite(r)]
    setorigins = [(seq_of[r['name']], r) for r in order if is_fwd_setorigin(r)]
    print("\n# Forward-flow check (set_origin must precede rewrite)")
    print(f"  forward-rewrite rules: {len(rewrites)} | forward set_origin rules: {len(setorigins)}")
    if rewrites and setorigins:
        first_rw = min(s for s, _ in rewrites)
        late = [(s, r) for s, r in setorigins if s > first_rw]
        if late:
            print(f"  [!] WARNING: {len(late)} set_origin rule(s) run AFTER the first forward-rewrite "
                  f"(seq#{first_rw}). These forwards will 404:")
            for s, r in late[:10]:
                print(f"        seq#{s} {r['name']}")
            if len(late) > 10:
                print(f"        ... and {len(late) - 10} more")
        else:
            print("  OK: every forward set_origin runs before the first forward-rewrite.")

    if args.mermaid_forward:
        # Compact "story" diagram of the forward flow, showing the REQUIRED order
        # (function -> set_origin -> rewrite) and whether the actual execution
        # order respects it. set_origin rules are collapsed into one node unless
        # --grep narrowed the selection, in which case the matched ones are shown.
        fn_nodes = [(seq_of[r['name']], r) for r in order if 'run_function' in r['behaviors']]
        so_nodes = [(seq_of[r['name']], r) for r in order if is_fwd_setorigin(r)]
        rw_nodes = [(seq_of[r['name']], r) for r in order if is_fwd_rewrite(r)]
        grep_so = [(s, r) for s, r in so_nodes if r in shown] if args.grep else []

        print("\n# Mermaid (forward flow - required order vs actual)")
        print("```mermaid")
        print("graph TD")
        if fn_nodes:
            fmin = min(s for s, _ in fn_nodes)
            print(f'    FUNC["proxy function(s)<br/>{len(fn_nodes)} run_function, first seq#{fmin}<br/>sets origin + uri headers"]')
        so_ids = []
        if grep_so:
            for s, r in grep_so:
                nid = 'SO_' + re.sub(r'\W', '_', r['name'])[:24]
                print(f'    {nid}["set_origin<br/>{r["name"][:30]} (seq#{s})<br/>reads origin header"]')
                so_ids.append((s, nid))
        elif so_nodes:
            smin = min(s for s, _ in so_nodes)
            smax = max(s for s, _ in so_nodes)
            print(f'    SO["set_origin rules<br/>{len(so_nodes)} rules, seq#{smin}-{smax}<br/>reads origin header"]')
            so_ids.append((smax, 'SO'))
        rw_ids = []
        for s, r in rw_nodes:
            nid = 'RW_' + re.sub(r'\W', '_', r['name'])[:24]
            print(f'    {nid}["forward-rewrite<br/>{r["name"][:30]} (seq#{s})<br/>reads uri header"]')
            rw_ids.append((s, nid))
        for _, sid in so_ids:
            if fn_nodes:
                print(f'    FUNC --> {sid}')
        for so_seq, sid in so_ids:
            for rw_seq, rid in rw_ids:
                bad = so_seq > rw_seq  # set_origin runs AFTER rewrite = wrong
                print(f'    {sid} {"-. WRONG: runs after rewrite .-> " if bad else "--> "}{rid}')
        first_so = min((s for s, _ in so_nodes), default=None)
        for s, rid in rw_ids:
            if first_so is not None and s < first_so:
                print(f'    class {rid} bad')
        print("    classDef bad fill:#fdd,stroke:#c00,stroke-width:2px;")
        print("```")


if __name__ == '__main__':
    main()
