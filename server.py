from flask.templating import render_template
import rethinkdb as r
import flask

import local_settings
from utils import DateTimeJSONEncoder, order_data_frame


app = flask.Flask(__name__,
                  static_folder="templates/static",
                  static_url_path="/static")


def get_db():
    return r.connect(local_settings.DB_HOST, 28015, db="mtrack")


@app.route('/')
def main():
    conn = get_db()
    init_data = r.table("packets").filter(r.row['timestamp'] > (r.now() - local_settings.TIMEOUT)).run(conn).items
    return render_template(
        "main.html",
        init_data=list(filter(bool, [process_packet(d) for d in init_data])),
        timeout=local_settings.TIMEOUT,
    )


def process_packet(d):
    if not 'sensor' in d:
        return

    if d["type"] == "Probe":
        output = {
            'event': 'stationSeen',
            'mac': d['mac'],
            'date': d['timestamp'],
            'essid': d['essid']
        }
    elif d["type"] == "Data":
        ap_mac, station_mac = order_data_frame(d, get_db())
        output = {
            'event': 'assocSeen',
            'station': station_mac,
            'ap': ap_mac,
            'date': d['timestamp']
        }
    elif d["type"] == "Beacon":
        output = {
            'event': 'APSeen',
            'essid': d["essid"],
            'bssid': d["mac"]
        }
    else:
        output = None

    if output:
        output['distance'] = abs(d['rssi'])
        output['sensor'] = 'S%d' % d['sensor']
        return output


def event_stream():
    conn = get_db()
    for packet in r.table('packets').changes().run(conn):
        data = process_packet(packet['new_val'])
        if data:
            yield ('data: %s\n\n' % DateTimeJSONEncoder().encode(data)).encode()


@app.route('/event_stream')
def stream():
    return flask.Response(event_stream(),
        mimetype="text/event-stream")


if __name__ == '__main__':
    app.debug = True
    app.run(threaded=True)
