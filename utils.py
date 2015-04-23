import datetime
import json
import rethinkdb as r

def order_data_frame(d, conn=None):
    mac_is_ap = bool(r.table('aps').get(d['mac']).run(conn))
    station_mac, ap_mac = ((d['mac2'], d['mac'])
                           if mac_is_ap else (
        d['mac'], d['mac2']))
    return ap_mac, station_mac


class DateTimeJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        else:
            return super(DateTimeJSONEncoder, self).default(obj)
