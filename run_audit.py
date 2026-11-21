import csv
import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / 'results'
RESULTS.mkdir(exist_ok=True)
LEAN = shutil.which('lean')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def lean_version():
    if not LEAN:
        return None
    p = subprocess.run([LEAN, '--version'], text=True, capture_output=True, timeout=20)
    return (p.stdout + p.stderr).strip()


def run_lean(case, source):
    path = RESULTS / (case + '.lean')
    path.write_text(source, encoding='utf-8')
    if not LEAN:
        return {'status': 'NOT_RUN', 'reason': 'Lean 4 not installed', 'sha256': digest(source.encode())}
    try:
        p = subprocess.run([LEAN, str(path)], text=True, capture_output=True, timeout=120)
        output = p.stdout + '\n' + p.stderr
        (RESULTS / (case + '.log')).write_text(output, encoding='utf-8')
        return {'status': 'OK' if p.returncode == 0 else 'ERROR', 'exit_code': p.returncode,
                'output': output, 'sha256': digest(source.encode())}
    except subprocess.TimeoutExpired:
        return {'status': 'ERROR', 'reason': 'Lean timeout', 'sha256': digest(source.encode())}


def audit(case, proof, goal='True', requested_goal=None, trusted_prelude=''):
    if requested_goal is not None and requested_goal != goal:
        return {'case': case, 'decision': 'REJECT', 'stage': 'A1', 'reason': 'statement mismatch'}
    # Prelude is controlled by the evaluator, not provided by an untrusted agent.
    source = f'{trusted_prelude}\ntheorem audited : {goal} := by\n{proof}\n#print axioms audited\n'
    run = run_lean(case, source)
    if run['status'] == 'NOT_RUN':
        return {'case': case, 'decision': 'NOT_RUN', 'stage': 'A3', 'reason': run['reason']}
    if run['status'] != 'OK':
        return {'case': case, 'decision': 'REJECT', 'stage': 'A3',
                'reason': run.get('reason', 'Lean rejected proof'), 'lean_exit_code': run.get('exit_code')}
    output = run['output']
    # Lean's documented message format is: 'audited' does not depend on any axioms
    # or: 'audited' depends on axioms: [axiomName, ...]
    no_axioms = re.search(r'\baudited\b.*does not depend on any axioms', output)
    depends = re.search(r'\baudited\b.*depends on axioms:\s*\[([^\]]*)\]', output, re.S)
    if no_axioms:
        return {'case': case, 'decision': 'ACCEPT', 'stage': 'A5',
                'reason': 'kernel accepted; no axiom dependencies', 'sha256': run['sha256']}
    if depends:
        return {'case': case, 'decision': 'REJECT', 'stage': 'A4',
                'reason': 'axiom dependencies: ' + depends.group(1).strip(), 'sha256': run['sha256']}
    return {'case': case, 'decision': 'REJECT', 'stage': 'A4',
            'reason': 'unrecognized axiom diagnostic (fail closed)', 'sha256': run['sha256']}


def main():
    cases = [
        audit('01_valid', '  trivial'),
        audit('02_sorry', '  sorry'),
        # The evaluator's test fixture declares an axiom to simulate a compromised proof.
        audit('03_custom_axiom', '  exact injected', trusted_prelude='axiom injected : True'),
        audit('04_statement_substitution', '  trivial', requested_goal='False'),
    ]
    expected = digest(b'trusted file v1')
    observed = digest(b'trusted file v2')
    cases.append({'case': '05_artifact_modified', 'decision': 'REJECT' if observed != expected else 'ACCEPT',
                  'stage': 'A2', 'reason': 'SHA-256 mismatch' if observed != expected else 'hash matched'})
    cases.append(audit('06_invalid_syntax', '  this_is_not_valid_lean'))
    expected_decisions = {'01_valid': 'ACCEPT', '02_sorry': 'REJECT', '03_custom_axiom': 'REJECT',
                          '04_statement_substitution': 'REJECT', '05_artifact_modified': 'REJECT',
                          '06_invalid_syntax': 'REJECT'}
    for case in cases:
        case['expected'] = expected_decisions[case['case']]
        case['matches_expected'] = (case['decision'] == case['expected']) if case['decision'] != 'NOT_RUN' else None
    result = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'lean_version': lean_version(),
              'lean_available': bool(LEAN), 'cases': cases}
    (RESULTS / 'results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    with (RESULTS / 'results.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=['case', 'decision', 'stage', 'reason', 'expected', 'matches_expected'], extrasaction='ignore')
        writer.writeheader()
        writer.writerows(cases)
    for case in cases:
        print(f"{case['case']}: {case['decision']} (expected {case['expected']}) [{case['stage']}]")
    if not LEAN:
        print('Lean not installed: kernel-dependent tests were NOT_RUN')
        raise SystemExit(2)
    if not all(c['matches_expected'] for c in cases):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
