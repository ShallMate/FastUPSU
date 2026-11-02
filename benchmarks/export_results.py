"""Export the measured protocol and module costs without changing raw records."""
import csv
import json


def export_results(root, jobs):
    fields = ['case', 'mode', 'nx_log2', 'ny_log2', 'network', 'status',
              'offline_seconds', 'online_seconds', 'total_seconds',
              'offline_MB', 'online_MB', 'total_MB',
              's3mt_online_seconds', 's3mt_online_MB']
    with (root/'summary.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for job in jobs:
            file = root/'raw'/job['case']/'result.json'
            if not file.exists():
                continue
            result = json.loads(file.read_text())
            row = {key: job[key] for key in fields if key in job}
            for key in ('status', 'offline_seconds', 'online_seconds', 'total_seconds', 's3mt_online_seconds'):
                if key in result:
                    row[key] = result[key]
            for key in ('offline', 'online', 'total', 's3mt_online'):
                if key+'_bytes' in result:
                    row[key+'_MB'] = result[key+'_bytes']/1_000_000
            writer.writerow(row)
