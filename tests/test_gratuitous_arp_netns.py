#!/usr/bin/env python3
"""Run as root inside a NEW empty network namespace; never on a live network.

sudo unshare --net python3 tests/test_gratuitous_arp_netns.py
Uses only virtual links and child namespaces. No packages or services installed.
"""
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

SCRIPT = str(Path(__file__).resolve())
BACKEND = str(Path(__file__).resolve().parent / 'support/garp_backend.rb')
VIP = '192.0.2.219'
MACS = {'a': '02:00:00:00:00:11', 'b': '02:00:00:00:00:12',
        'c': '02:00:00:00:00:13', 'd': '02:00:00:00:00:14',
        'x': '02:00:00:00:00:15', 'z': '02:00:00:00:00:16',
        'router': '02:00:00:00:00:fe'}
IPS = {name: '192.0.2.' + str(11 + i) for i, name in enumerate(MACS)}
IPS['router'] = '192.0.2.254'


def mac(value):
    return bytes.fromhex(value.replace(':', ''))


def frame(sender='a', spa=VIP, tpa=None, op=1, tha='00:00:00:00:00:00',
          eth_dst='ff:ff:ff:ff:ff:ff', eth_src=None, sha=None,
          htype=1, ptype=0x800, hlen=6, plen=4, etype=0x806):
    eth_src = eth_src or MACS[sender]
    sha = sha or MACS[sender]
    # Variable lengths deliberately create structurally consistent malformed ARP.
    body = struct.pack('!HHBBH', htype, ptype, hlen, plen, op)
    body += mac(sha)[:hlen].ljust(hlen, b'\0')
    body += socket.inet_aton(spa)[:plen].ljust(plen, b'\0')
    body += mac(tha)[:hlen].ljust(hlen, b'\0')
    body += socket.inet_aton(tpa or spa)[:plen].ljust(plen, b'\0')
    return mac(eth_dst) + mac(eth_src) + struct.pack('!H', etype) + body


def worker():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind(('eth0', 0))
    sock.setblocking(False)
    print('READY', flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        if request['op'] == 'send':
            for packet in request['packets']:
                sock.send(bytes.fromhex(packet))
            result = len(request['packets'])
        else:
            result = []
            while select.select([sock], [], [], 0)[0]:
                packet, addr = sock.recvfrom(65535)
                if addr[2] != socket.PACKET_OUTGOING:
                    result.append(packet.hex())
        print(json.dumps(result), flush=True)


class Lab:
    def __init__(self):
        self.namespaces = {}
        self.workers = {}
        self.directory = tempfile.TemporaryDirectory(prefix='vnfilter-garp-')
        self.checks = 0
        self.daemons = []

    def command(self, ns, *args, **kwargs):
        prefix = ['nsenter', '-t', str(self.namespaces[ns].pid), '-n'] if ns else []
        return subprocess.check_output(prefix + list(args), text=True, stderr=subprocess.PIPE, **kwargs)

    def namespace(self, name):
        process = subprocess.Popen(['unshare', '--net', 'sleep', '3600'])
        self.namespaces[name] = process
        for _ in range(100):
            if os.readlink(f'/proc/{process.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                return
            time.sleep(0.01)
        raise RuntimeError('namespace did not start')

    def bridge(self, ns, name, vlan=False):
        self.command(ns, 'ip', 'link', 'add', name, 'type', 'bridge', 'vlan_filtering', str(int(vlan)))
        self.command(ns, 'ip', 'link', 'set', name, 'up')

    def link(self, left, lname, lbridge, right, rname, rbridge=None):
        # All creation starts in the outer, isolated namespace.
        self.command(None, 'ip', 'link', 'add', 'testleft', 'type', 'veth', 'peer', 'name', 'testright')
        for ns, old, new, bridge in [(left, 'testleft', lname, lbridge), (right, 'testright', rname, rbridge)]:
            if ns:
                self.command(None, 'ip', 'link', 'set', old, 'netns', str(self.namespaces[ns].pid))
            self.command(ns, 'ip', 'link', 'set', old, 'name', new)
            if bridge:
                self.command(ns, 'ip', 'link', 'set', new, 'master', bridge)
            self.command(ns, 'ip', 'link', 'set', new, 'up')

    def backend(self, ns, *args):
        return self.command(ns, 'ruby', BACKEND, *args)

    def guard(self, host, mode='enforce', targets=None):
        if targets is None:
            targets = [IPS['a'], IPS['c'], VIP] if host == 'h1' else [IPS['b'], IPS['d'], VIP]
        self.backend(host, 'guard', mode, self.directory.name + '/' + host, *targets)

    def rpc(self, name, request):
        process = self.workers[name]
        process.stdin.write(json.dumps(request) + '\n')
        process.stdin.flush()
        if not select.select([process.stdout], [], [], 10)[0]:
            raise RuntimeError('packet worker timed out')
        return json.loads(process.stdout.readline())

    def guard_count(self, key):
        state = json.loads(self.command('h1', 'nft', '-j', 'list', 'table', 'bridge', 'one_arp_guard'))
        return sum(expr['counter']['packets'] for item in state['nftables']
                   if 'rule' in item and any(key in e for e in item['rule']['expr'])
                   for expr in item['rule']['expr'] if 'counter' in expr)

    def check(self, label, sender, packet, delivered, blocked=(), garp=None):
        before = self.guard_count('accept') if garp is not None else None
        for name in set(delivered) | set(blocked):
            self.rpc(name, {'op': 'drain'})
        self.rpc(sender, {'op': 'send', 'packets': [packet.hex()]})
        time.sleep(0.025)
        for name in set(delivered) | set(blocked):
            received = self.rpc(name, {'op': 'drain'})
            found = any(bytes.fromhex(p).startswith(packet) for p in received)
            assert found == (name in delivered), (label, name, found)
        if garp is not None:
            assert self.guard_count('accept') - before == int(garp), ('guard exemption', label)
        self.checks += 1

    def setup(self):
        self.bridge(None, 'wire')
        for name in ['h1', 'h2', *MACS]:
            self.namespace(name)
        for host in ['h1', 'h2']:
            self.bridge(host, 'br0', vlan=True)
            self.link(None, host, 'wire', host, 'bond0.1', 'br0')
            self.command(host, 'ebtables', '-t', 'nat', '-N', 'unrelated', '-P', 'ACCEPT')
        self.bridge('h1', 'br-other')
        self.link(None, 'router', 'wire', 'router', 'eth0')
        for i, (name, host, bridge) in enumerate([
                ('a', 'h1', 'br0'), ('b', 'h2', 'br0'), ('c', 'h1', 'br0'),
                ('d', 'h2', 'br0'), ('x', 'h1', 'br0'), ('z', 'h1', 'br-other')], 1):
            tap = f'one-{i}-0'
            self.link(host, tap, bridge, name, 'eth0')
            if name == 'x':
                self.command(host, 'bridge', 'vlan', 'del', 'dev', tap, 'vid', '1')
                self.command(host, 'bridge', 'vlan', 'add', 'dev', tap, 'vid', '2', 'pvid', 'untagged')
            self.backend(host, 'build', tap, MACS[name], IPS[name], *([VIP] if name in ['a', 'b', 'd'] else []))
        for name in MACS:
            self.command(name, 'ip', 'link', 'set', 'eth0', 'address', MACS[name])
            self.command(name, 'ip', 'addr', 'add', IPS[name] + '/24', 'dev', 'eth0')
            process = subprocess.Popen(['nsenter', '-t', str(self.namespaces[name].pid), '-n',
                                        'python3', SCRIPT, '--worker'], text=True,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.workers[name] = process
            assert process.stdout.readline().strip() == 'READY'
        for host in ['h1', 'h2']:
            self.guard(host)
            self.backend(host, 'refresh', '--check')

    def run(self):
        self.setup()
        print('Two isolated hosts, shared-IP peers, ordinary client, alias client, VLAN and bridge controls ready', flush=True)
        for sender in ['a', 'b']:
            for op in [1, 2]:
                for tha in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff']:
                    self.check('shared GARP', sender, frame(sender, op=op, tha=tha),
                               ['c', 'd', 'b' if sender == 'a' else 'a'], ['x', 'z'])
        # Router address has no VM owner and no target-set entry.
        for op in [1, 2]:
            self.check('upstream GARP', 'router', frame('router', spa=IPS['router'], op=op), ['a', 'b', 'c', 'd'], garp=True)
        self.check('owned request', 'router', frame('router', spa=IPS['router'], tpa=IPS['c']), ['c'], ['a', 'b', 'd'])
        self.check('ordinary reply', 'router', frame('router', spa=IPS['router'], tpa=IPS['c'], op=2,
                                                  tha=MACS['c'], eth_dst=MACS['c']), ['c'])
        self.check('wrong reply MAC', 'router', frame('router', spa=IPS['router'], tpa=IPS['c'], op=2), [], ['c'])
        for changes in [dict(spa='192.0.2.220'), dict(eth_src=MACS['b']), dict(sha=MACS['b'])]:
            for op in [1, 2]:
                self.check('forged VM GARP', 'a', frame(op=op, **changes), [], ['b', 'c', 'd'])
        for changes in [dict(spa='0.0.0.0'), dict(hlen=5), dict(hlen=7), dict(plen=3),
                        dict(plen=5), dict(htype=2), dict(ptype=0x86dd), dict(op=3),
                        dict(op=4), dict(eth_dst=MACS['c'])]:
            self.check('non-announcement', 'router', frame('router', **changes), [], ['c'], garp=False)
        self.check('truncated ARP', 'router', frame('router')[:-1], [], ['c'], garp=False)
        # Two nonzero addresses cover zero in every position, without changing
        # the other repeated values (including even low nibbles).
        equal_addresses = [value * 0x11111111 for value in range(1, 16)] + [1, 0x10000000]
        assert all({(address >> shift) & 15 for address in equal_addresses} == set(range(16))
                   for shift in range(0, 32, 4))
        for value in equal_addresses:
            address = str(ipaddress.IPv4Address(value))
            self.check('equal nibble pairs ' + address, 'router', frame('router', spa=address), ['c'], garp=True)
        # Every single differing bit must fail the nft equality comparison.
        base = int(ipaddress.IPv4Address('198.51.100.97'))
        for bit in range(32):
            packet = frame('router', spa=str(ipaddress.IPv4Address(base)),
                           tpa=str(ipaddress.IPv4Address(base ^ (1 << bit))))
            self.check('unequal IP bit ' + str(bit), 'router', packet, [], ['c'], garp=False)
        # Prove guard suppression independently of per-VM filters with counters.
        before = self.command('h1', 'nft', '-j', 'list', 'table', 'bridge', 'one_arp_guard')
        scan = frame('router', spa=IPS['router'], tpa='192.0.2.250')
        self.rpc('router', {'op': 'send', 'packets': [scan.hex()] * 1000})
        time.sleep(0.1)
        after = self.command('h1', 'nft', '-j', 'list', 'table', 'bridge', 'one_arp_guard')
        def drops(raw):
            return sum(expr['counter']['packets'] for item in json.loads(raw)['nftables']
                       if 'rule' in item and any('drop' in e for e in item['rule']['expr'])
                       for expr in item['rule']['expr'] if 'counter' in expr)
        assert drops(after) - drops(before) == 1000
        self.check('GARP after scan burst', 'b', frame('b'), ['a', 'c', 'd'])
        # Existing VM update, duplicate reconciliation, rollback, and reapply.
        self.backend('h1', 'refresh', '--remove')
        self.check('old client rules reject GARP', 'b', frame('b'), ['a'], ['c'])
        self.backend('h1', 'refresh', '--apply')
        dump = self.command('h1', 'ebtables-save')
        self.backend('h1', 'refresh', '--apply')
        assert [l for l in dump.splitlines() if not l.startswith('#')] == [
            l for l in self.command('h1', 'ebtables-save').splitlines() if not l.startswith('#')]
        self.backend('h1', 'refresh', '--check')
        self.check('existing client refreshed', 'b', frame('b'), ['c'])
        # A lifecycle cleanup/rebuild changes only its own NIC chains.
        foreign_before = self.command('h1', 'ebtables', '-t', 'nat', '-L', 'unrelated')
        self.backend('h1', 'cleanup', 'one-3-0')
        self.backend('h1', 'build', 'one-3-0', MACS['c'], IPS['c'])
        assert self.command('h1', 'ebtables', '-t', 'nat', '-L', 'unrelated') == foreign_before
        self.check('client rebuilt after lifecycle cleanup', 'b', frame('b'), ['c'])
        # Alias detach removes sender permission, while receiving still works.
        self.backend('h1', 'cleanup', 'one-1-0', VIP)
        self.check('detached source alias', 'a', frame('a'), [], ['b', 'c', 'd'])
        self.check('peer without alias receives', 'b', frame('b'), ['a', 'c'])
        self.backend('h1', 'build', 'one-1-0', MACS['a'], IPS['a'], VIP)
        self.check('reattached source alias', 'a', frame('a'), ['b', 'c', 'd'])
        # Actual Linux neighbor cache and reachability across a manual VIP move.
        self.command('a', 'ip', 'addr', 'add', VIP + '/32', 'dev', 'eth0')
        self.command('c', 'ip', 'neigh', 'replace', VIP, 'lladdr', MACS['a'], 'nud', 'reachable', 'dev', 'eth0')
        self.command('c', 'ping', '-c', '1', '-W', '1', VIP)
        self.command('a', 'ip', 'addr', 'del', VIP + '/32', 'dev', 'eth0')
        self.command('b', 'ip', 'addr', 'add', VIP + '/32', 'dev', 'eth0')
        time.sleep(1.1)  # Linux neighbor locktime, not neighbor expiry.
        self.rpc('b', {'op': 'send', 'packets': [frame('b', tha='ff:ff:ff:ff:ff:ff').hex()] * 5})
        neighbor = json.loads(self.command('c', 'ip', '-j', 'neigh', 'show', VIP, 'dev', 'eth0'))
        assert neighbor[0]['lladdr'] == MACS['b'], neighbor
        self.command('c', 'ping', '-c', '2', '-W', '1', VIP)
        print('Shared VIP moved between different parent MACs; stale client neighbor updated; ping 2/2', flush=True)
        if len(sys.argv) == 3 and sys.argv[1] == '--keepalived':
            self.keepalived(sys.argv[2])
        else:
            print('SKIP: Keepalived takeover (supply --keepalived /path/to/binary)', flush=True)
        # Guard modes and repeated set replacement, including no local owners.
        for mode in ['observe', 'disabled', 'enforce', 'enforce']:
            self.guard('h1', mode, [])
            self.check('empty target set GARP ' + mode, 'router', frame('router', spa=IPS['router']), ['c'])
        # Capture backend state as reproducible evidence, without host identifiers.
        print(self.command('h1', 'ebtables-save'), flush=True)
        print(self.command('h1', 'nft', 'list', 'table', 'bridge', 'one_arp_guard'), flush=True)
        print(f'PASS: {self.checks} packet cases; 1000/1000 unowned requests suppressed; shared-IP failover and reconciliation', flush=True)

    def keepalived(self, binary):
        self.command('b', 'ip', 'addr', 'del', VIP + '/32', 'dev', 'eth0')
        def owns(name):
            data = json.loads(self.command(name, 'ip', '-j', 'addr', 'show', 'dev', 'eth0'))
            return any(a['local'] == VIP for link in data for a in link['addr_info'])

        def wait_owner(name):
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                if owns(name):
                    return
                time.sleep(0.1)
            raise AssertionError('Keepalived did not acquire VIP: ' + name)

        for name, peer, priority in [('a', 'b', 150), ('b', 'a', 100)]:
            directory = Path(self.directory.name) / name
            directory.mkdir()
            config = directory / 'keepalived.conf'
            config.write_text(f'''global_defs {{
    router_id GARP_{name}
}}
vrrp_instance TEST {{
    state BACKUP
    interface eth0
    virtual_router_id 219
    priority {priority}
    advert_int 1
    unicast_src_ip {IPS[name]}
    unicast_peer {{
        {IPS[peer]}
    }}
    virtual_ipaddress {{
        {VIP}/32 dev eth0
    }}
}}
''')
            log = open(directory / 'keepalived.log', 'w')
            # Private /run prevents runtime writes from reaching the host.
            command = ['unshare', '--mount', '--propagation', 'private', 'sh', '-c',
                       'mount -t tmpfs tmpfs /run && exec "$@"', 'sh',
                       'nsenter', '-t', str(self.namespaces[name].pid), '-n', binary,
                       '-n', '-l', '-G', '-P', '-R', '-f', str(config),
                       '-p', str(directory / 'parent.pid'), '-r', str(directory / 'vrrp.pid')]
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            log.close()
            self.daemons.append(process)
        wait_owner('a')
        time.sleep(1)
        assert not owns('b'), 'Keepalived peers must elect one master'
        self.command('c', 'ip', 'neigh', 'replace', VIP, 'lladdr', MACS['a'], 'nud', 'reachable', 'dev', 'eth0')
        self.command('c', 'ping', '-c', '1', '-W', '1', VIP)
        for name in ['c', 'd']:
            self.rpc(name, {'op': 'drain'})
        os.killpg(self.daemons[0].pid, signal.SIGSTOP)
        self.command('a', 'ip', 'link', 'set', 'eth0', 'down')
        wait_owner('b')
        time.sleep(0.2)
        neighbor = json.loads(self.command('c', 'ip', '-j', 'neigh', 'show', VIP, 'dev', 'eth0'))
        assert neighbor[0]['lladdr'] == MACS['b'], neighbor
        for name in ['c', 'd']:
            captured = self.rpc(name, {'op': 'drain'})
            expected = frame('b', tha='ff:ff:ff:ff:ff:ff')
            assert any(bytes.fromhex(p).startswith(expected) for p in captured), ('Keepalived GARP missing', name)
        self.command('c', 'ping', '-c', '2', '-W', '1', VIP)
        print('PASS: Keepalived unicast election and master failure; automatic VIP takeover, GARP to ordinary/alias clients, neighbor update, ping 2/2', flush=True)
        for name in ['a', 'b']:
            print((Path(self.directory.name) / name / 'keepalived.log').read_text(), flush=True)

    def close(self):
        for process in self.daemons:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGCONT)
                os.killpg(process.pid, signal.SIGTERM)
        for process in self.daemons:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for process in [*self.workers.values(), *self.namespaces.values()]:
            process.terminate()
        for process in [*self.workers.values(), *self.namespaces.values()]:
            process.wait(timeout=10)
        self.directory.cleanup()


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        worker()
    else:
        links = json.loads(subprocess.check_output(['ip', '-j', 'link'], text=True))
        if os.geteuid() or [link['ifname'] for link in links] != ['lo']:
            sys.exit('Refusing: run as root under unshare --net with only lo present')
        lab = Lab()
        try:
            lab.run()
        except subprocess.CalledProcessError as error:
            print(error.stderr, file=sys.stderr)
            raise
        finally:
            lab.close()
