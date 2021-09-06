import sys
import dns_server
import os
import traceback
from easyzone import easyzone
from constants import ZONE_FILE_EXT


def load_zones(config_dir):
    zones_list = []  # {zone_info}
    try:
        for zone_file in os.listdir(config_dir):
            path = os.path.join(config_dir, zone_file)
            if os.path.isfile(path) and zone_file.find(ZONE_FILE_EXT) != -1:
                domain_name = zone_file[:zone_file.rfind('.')]
                zone_info = easyzone.zone_from_file(domain_name, path)
                zones_list.append(zone_info)
    except:
        print(f'error ocuured while reading zone files in dir : {config_dir}')
        traceback.print_exc()
    return zones_list


def run_dns_server(CONFIG, IP, PORT):
    zones = load_zones(CONFIG)
    server = dns_server.DNSServer(IP, int(PORT), zones)
    server.start_server()


# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)
