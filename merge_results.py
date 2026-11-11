#!/usr/bin/env python3
"""Merge per-run summaries; keep each network and timestamp separate."""
import argparse
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='汇总多个测试目录内的summary.csv，不混合不同网络的统计')
    parser.add_argument('directory', help='存放所有测试结果的目录')
    parser.add_argument('--out', default='all_results.csv')
    args = parser.parse_args()
    files = sorted(Path(args.directory).rglob('summary.csv'))
    if not files:
        parser.error('没有找到summary.csv')
    destination = Path(args.out)
    if any(file.resolve() == destination.resolve() for file in files):
        parser.error('输出文件不能覆盖输入summary.csv')
    rows = []
    fields = ['source_file']
    for file in files:
        with file.open(encoding='utf-8-sig', newline='') as handle:
            for row in csv.DictReader(handle):
                row['source_file'] = str(file)
                rows.append(row)
                for field in row:
                    if field not in fields:
                        fields.append(field)
    with destination.open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f'已汇总{len(files)}个文件、{len(rows)}条记录至 {destination}')


if __name__ == '__main__':
    main()
