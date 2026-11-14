#!/usr/bin/env python3
"""Cross-platform IPv4 ICMP sampling. Python 3.9+, standard library only."""
import argparse
import concurrent.futures
import csv
import datetime as dt
import json
import locale
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import statistics
import subprocess
import time
import urllib.request

TARGETS = [('JP', 'hnd-jp-ping.vultr.com'),
           ('SG', 'sgp-ping.vultr.com'), ('US', 'lax-ca-us-ping.vultr.com')]


def run(command, timeout=12):
    env = dict(os.environ, LC_ALL='C', LANG='C')
    try:
        p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, env=env)
        raw = p.stdout
        encodings = ['utf-8-sig', locale.getpreferredencoding(False), 'gb18030']
        for encoding in dict.fromkeys(encodings):
            try:
                return p.returncode, raw.decode(encoding)
            except UnicodeError:
                pass
        return p.returncode, raw.decode('utf-8', errors='replace')
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def network_info(system):
    info = {'interface': None, 'connection_type': 'unknown',
            'note': '默认 IPv4 接口的推断；多网卡、VPN、虚拟接口可能影响结果。不采集 Wi-Fi 名称。'}
    try:
        if system == 'win':
            script = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                      "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
                      "Where-Object {$_.NextHop -ne '0.0.0.0'} | "
                      "Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}} | Select-Object -First 1; "
                      "if($r){Get-NetAdapter -InterfaceIndex $r.InterfaceIndex | "
                      "Select-Object Name,InterfaceDescription,PhysicalMediaType | ConvertTo-Json -Compress}")
            code, output = run(['powershell.exe', '-NoProfile', '-Command', script])
            adapter = json.loads(output) if code == 0 and output.strip() else {}
            info['interface'] = adapter.get('Name')
            media = str(adapter.get('PhysicalMediaType', ''))
            text = ' '.join(str(v) for v in adapter.values()).lower()
            if media in ('1', '9') or any(x in text for x in ('802.11', 'wireless', 'wi-fi', 'wifi')):
                info['connection_type'] = 'wifi'
            elif media == '14' or '802.3' in text:
                info['connection_type'] = 'ethernet'
        elif system == 'linux':
            code, output = run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'])
            routes = json.loads(output) if code == 0 else []
            interface = routes[0].get('dev') if routes else None
            info['interface'] = interface
            if interface:
                base = Path('/sys/class/net') / interface
                if (base / 'wireless').exists() or (base / 'phy80211').exists():
                    info['connection_type'] = 'wifi'
                elif (base / 'device').exists() and (base / 'type').read_text().strip() == '1':
                    info['connection_type'] = 'ethernet'
        else:
            _, output = run(['route', '-n', 'get', 'default'])
            match = re.search(r'interface:\s*(\S+)', output)
            interface = match.group(1) if match else None
            info['interface'] = interface
            _, output = run(['networksetup', '-listallhardwareports'])
            for block in output.split('\n\n'):
                if interface and re.search(r'Device:\s*' + re.escape(interface) + r'\s*(?:\n|$)', block):
                    if 'Wi-Fi' in block or 'AirPort' in block:
                        info['connection_type'] = 'wifi'
                    elif 'Ethernet' in block:
                        info['connection_type'] = 'ethernet'
    except (ValueError, OSError, IndexError, TypeError) as exc:
        info['detection_error'] = str(exc)
    return info


def lookup_isp():
    # Explicit opt-in: this request exposes the current egress IP to this provider.
    try:
        request = urllib.request.Request('https://ipwho.is/', headers={'User-Agent': 'network-test/1.0'})
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.load(response)
        if not data.get('success'):
            raise ValueError(data.get('message', 'lookup failed'))
        connection = data.get('connection') or {}
        # Deliberately do not persist the tester's public IP or precise location.
        return {'status': 'ok', 'source': 'https://ipwho.is/',
                'isp': connection.get('isp'), 'organization': connection.get('org'),
                'asn': connection.get('asn'),
                'note': '仅代表查询时的公网出口组织，不一定是实际接入运营商。'}
    except Exception as exc:
        return {'status': 'failed', 'error': str(exc)}


def sample_target(label, host, args, system, folder):
    result = {'target': label, 'host': host, 'ipv4': None, 'status': 'pending',
              'attempted': 0, 'received': 0, 'loss_percent': None,
              'min_ms': None, 'avg_ms': None, 'max_ms': None, 'latency_samples': 0,
              'latency_upper_bound_samples': 0}
    log = []
    latencies = []
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
        result['ipv4'] = ip
    except OSError as exc:
        result.update(status='dns_error', error=str(exc))
        (folder / f'{label}.log').write_text(str(exc), encoding='utf-8')
        return result
    for index in range(args.count):
        start = time.monotonic()
        if system == 'win':
            command = ['ping', '-4', '-n', '1', '-w', str(args.timeout * 1000), ip]
        elif system == 'linux':
            command = ['ping', '-4', '-n', '-c', '1', '-W', str(args.timeout), ip]
        else:
            command = ['ping', '-n', '-c', '1', '-W', str(args.timeout * 1000), ip]
        code, output = run(command, timeout=args.timeout + 5)
        log.append(f'--- sample {index + 1}: exit={code} ---\ncommand: {command!r}\n{output}')
        # Apple's ping uses 2 for no echo replies; Linux uses 1 instead.
        normal_codes = (0, 2) if system == 'mac' else (0, 1)
        if code not in normal_codes or re.search(r'operation not permitted|permission denied|not recognized|无权|不是内部', output, re.I):
            result.update(status='command_error', error=output.strip() or f'ping exit code {code}')
            break
        result['attempted'] += 1
        # Match the echo reply line only. Windows may return exit=0 for unreachable replies.
        reply = next((line for line in output.splitlines()
                      if re.search(r'\bttl\s*[=:]', line, re.I)), None)
        if reply:
            result['received'] += 1
            match = re.search(r'(?:time|时间|時間)\s*([=<])\s*([\d.,]+)\s*(?:ms|毫秒)', reply, re.I)
            if match:
                value = float(match.group(2).replace(',', '.'))
                latencies.append(value)
                if match.group(1) == '<':
                    result['latency_upper_bound_samples'] += 1
        if index < args.count - 1:
            time.sleep(max(0, 1 - (time.monotonic() - start)))
    (folder / f'{label}.log').write_text('\n'.join(log), encoding='utf-8')
    if result['attempted']:
        result['loss_percent'] = round(100 * (1 - result['received'] / result['attempted']), 2)
    result['latency_samples'] = len(latencies)
    if latencies:
        result.update(min_ms=round(min(latencies), 3), avg_ms=round(statistics.mean(latencies), 3),
                      max_ms=round(max(latencies), 3))
    if result['status'] == 'pending':
        result['status'] = 'completed' if result['received'] else 'no_echo_reply'
    return result


def main():
    parser = argparse.ArgumentParser(description='IPv4 ping 测试，输出 CSV、JSON 和原始日志；不测试代理可用性。')
    systems = parser.add_mutually_exclusive_group()
    for name in ('win', 'mac', 'linux'):
        systems.add_argument('--' + name, dest='system', action='store_const', const=name)
    parser.add_argument('--count', type=int, default=30, help='每个目标请求数，默认30')
    parser.add_argument('--timeout', type=int, default=2, help='单个回复超时秒数，默认2')
    parser.add_argument('--tester', default='anonymous', help='测试者编号，例如T01')
    parser.add_argument('--region', default='', help='手动填写省市')
    parser.add_argument('--isp', default='', help='手动填写实际接入运营商')
    parser.add_argument('--connection', choices=['wifi', 'ethernet', 'hotspot', 'unknown'], help='手动标记连接方式')
    parser.add_argument('--detect-isp', action='store_true', help='允许请求第三方公网IP信息服务以推断出口运营商')
    parser.add_argument('--target', action='append', help='自定义目标域名或IPv4，可重复；替代默认目标')
    parser.add_argument('--out', default='results', help='结果根目录，默认results')
    args = parser.parse_args()
    actual = {'Windows': 'win', 'Darwin': 'mac', 'Linux': 'linux'}.get(platform.system())
    if not actual or (args.system and args.system != actual):
        parser.error('系统参数与当前系统不符，或当前系统不受支持')
    if not 1 <= args.count <= 1000 or not 1 <= args.timeout <= 30:
        parser.error('count必须为1～1000，timeout必须为1～30')
    if not shutil.which('ping'):
        parser.error('找不到ping命令；Ubuntu/Debian可安装iputils-ping后重试')
    started = dt.datetime.now(dt.timezone.utc)
    folder = Path(args.out) / started.strftime('%Y%m%dT%H%M%S%fZ')
    folder.mkdir(parents=True, exist_ok=False)
    metadata = {'tester': args.tester, 'region_manual': args.region, 'isp_manual': args.isp,
                'started_utc': started.isoformat(), 'started_local': dt.datetime.now().astimezone().isoformat(),
                'system': platform.system(), 'system_version': platform.release(),
                'network': network_info(actual), 'connection_manual': args.connection,
                'isp_lookup': lookup_isp() if args.detect_isp else {'status': 'disabled'}}
    targets = [(f'T{i+1}', h) for i, h in enumerate(args.target)] if args.target else TARGETS
    print(f'输出目录：{folder}\n网络信息：{json.dumps(metadata["network"], ensure_ascii=False)}', flush=True)
    print('开始测试；每个目标顺序采样，不同目标并行。请等待完成。', flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(sample_target, label, host, args, actual, folder) for label, host in targets]
        results = [future.result() for future in futures]
    report = {'metadata': metadata, 'settings': {'count': args.count, 'timeout_seconds': args.timeout},
              'results': results}
    (folder / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    rows = []
    for result in results:
        rows.append({'tester': args.tester, 'region_manual': args.region, 'isp_manual': args.isp,
                     'isp_detected': metadata['isp_lookup'].get('isp', ''),
                     'connection_detected': metadata['network']['connection_type'],
                     'connection_manual': args.connection or '', 'started_utc': metadata['started_utc'],
                     'system': metadata['system'], **result})
        loss = f'{result["loss_percent"]}%' if result['loss_percent'] is not None else '未统计'
        latency = f'{result["avg_ms"]} ms' if result['avg_ms'] is not None else '无数据'
        print(f'{result["target"]} {result["ipv4"] or result["host"]}: '
              f'{result["status"]}, 收到 {result["received"]}/{result["attempted"]}, '
              f'丢包 {loss}, 平均 {latency}')
        if result.get('error'):
            print(f'  错误详情：{result["error"]}\n  原始日志：{folder / (result["target"] + ".log")}')
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (folder / 'summary.csv').open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print('已保存 summary.csv、report.json 和各目标原始日志。')
    return 1 if any(r['status'] in ('dns_error', 'command_error') for r in results) else 0


if __name__ == '__main__':
    raise SystemExit(main())
