"""Send existing backend configuration to the linked Vercel project through stdin."""
from pathlib import Path
import json
import secrets
import argparse
import subprocess
from dotenv import dotenv_values, set_key

parser = argparse.ArgumentParser()
parser.add_argument('--project', required=True, help='Exact linked project name to configure')
parser.add_argument('--scope', required=True, help='Vercel account or team scope')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
link = json.loads((root / '.vercel/project.json').read_text())
if link.get('projectName') != args.project:
    raise SystemExit('The linked Vercel project does not match --project. No secrets were sent.')
values = dict(dotenv_values(root / '.env'))
if not values.get('REPORT_SIGNING_SECRET'):
    values['REPORT_SIGNING_SECRET'] = secrets.token_urlsafe(48)
    set_key(root / '.env', 'REPORT_SIGNING_SECRET', values['REPORT_SIGNING_SECRET'])
    (root / '.env').chmod(0o600)
for key in ['NVIDIA_API_KEY', 'NVIDIA_MODEL', 'GITHUB_TOKEN', 'REPORT_SIGNING_SECRET']:
    if not values.get(key):
        continue
    for target in ['production', 'preview']:
        command = ['vercel', 'env', 'add', key, target, '--yes', '--scope', args.scope]
        if key != 'NVIDIA_MODEL':
            command.append('--sensitive')
        result = subprocess.run(command, input=values[key], text=True, capture_output=True, cwd=root)
        if result.returncode:
            # Do not print captured stdin, provider responses, or secret values.
            raise SystemExit(f'Could not configure {key} for {target}. Inspect environment names with vercel env ls.')
        print(f'Configured {key} for {target}; value hidden.', flush=True)
