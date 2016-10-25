import subprocess
import struct

import scapy.all as sp
import rethinkdb as r

import local_settings
from utils import order_data_frame


dBm = lambda x: -(256 - x)

r.connect(local_settings.DB_HOST, 28015, db="mtrack").repl()

try:
    r.db_create('mtrack').run()
except r.RqlRuntimeError:
    pass

try:
    r.table_create('packets').run()
except r.RqlRuntimeError:
    pass
try:
    r.table_create('stations', primary_key='mac').run()
except r.RqlRuntimeError:
    pass
try:
    r.table_create('aps', primary_key='bssid').run()
except r.RqlRuntimeError:
    pass


def get_rssi(packet):
    rssi = dBm(packet.notdecoded[0x16 - local_settings.OFFSET])
    try:
        rssi2 = dBm(packet.notdecoded[0x1A - local_settings.OFFSET])
    except IndexError:
        rssi2 = rssi

    return (rssi, rssi2)


def infer(d):
    if d['type'] == 'Beacon':
        r.table("aps").insert({
            'bssid': d['mac'],
            'essid': d['essid'],
            "lastSeen": r.now()
        }, conflict="update").run()
    elif d['type'] == 'Probe':
        r.table('stations').insert({
            'mac': d['mac'], 'probes': [], 'aps': []}).run()
        if len(d['essid']):
            r.table('stations').get(d['mac']).update({
                'probes': r.branch(~r.row['probes'].contains(d['essid']),
                                   r.row['probes'].append(d['essid']),
                                   r.row['probes']),
                "lastSeen": r.now()
            }).run()
    elif d['type'] == 'Data':
        ap_mac, station_mac = order_data_frame(d)
        r.table('stations').insert({
            'mac': station_mac, 'probes': [], 'aps': []}).run()
        r.table('stations').get(station_mac).update({
            'aps': r.branch(~r.row['aps'].contains(ap_mac),
                            r.row['aps'].append(ap_mac),
                            r.row['aps']),
            "lastSeen": r.now()
        }).run()


def process(pkt):
    global last_packet
    last_packet = pkt

    if pkt.type == 0:
        # Management

        if pkt.subtype == 4:
            # Probe Request
            d = {
                "type": "Probe",
                "mac": pkt.addr2,
                "essid": pkt.info if hasattr(pkt, "info") else None
            }
        elif pkt.subtype == 8:
            # Beacon
            d = {
                "type": "Beacon",
                "essid": pkt.info,
                "mac": pkt.addr2
            }
        elif pkt.subtype == 13:
            # Acknowledgement
            return
        elif pkt.subtype == 12:
            # QoS
            d = {
                "type": "QoS",
                "mac": pkt.addr2
            }
        elif pkt.subtype == 5:
            # Probe response
            return
        else:
            # Unknown subtype
            return
    elif pkt.type == 2:
        # Data
        d = {
            "type": "Data",
            "mac": pkt.addr2,
            "mac2": pkt.addr1,
            "size": len(pkt.payload)
        }
    elif pkt.type == 1:
        # Control
        return
    else:
        pkt.show()
        return

    if not pkt.sprintf("%RadioTap.present%").startswith("TSFT+Flags+Rate+Channel+dBm_AntSignal"):
        # weird packet
        return

    r1, r2 = get_rssi(pkt)
    if "essid" in d:
        d['essid'] = d['essid'].decode('utf8', errors='replace').replace('\x00', '')
    d['rssi'] = r1
    d['rssi2'] = r2
    d['freq'] = struct.unpack("h", pkt.notdecoded[0x12 - local_settings.OFFSET:0x14 - local_settings.OFFSET])[0]
    d['timestamp'] = r.now()
    d['sensor'] = local_settings.SENSOR_ID

    r.table('packets').insert(d).run()
    infer(d)
    # pprint.pprint(d)


if __name__ == '__main__':
    print("Sensor ID %d" % local_settings.SENSOR_ID)
    p = subprocess.Popen(
        ("/usr/bin/sudo /usr/sbin/tcpdump -q -U -w - -i "+local_settings.INTERFACE).split(" "),
        stdout=subprocess.PIPE)
    try:
        sp.sniff(offline=p.stdout, store=0, prn=process)
    finally:
        p.stdout.close()