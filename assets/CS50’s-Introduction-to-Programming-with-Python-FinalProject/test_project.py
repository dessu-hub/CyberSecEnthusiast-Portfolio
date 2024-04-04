import pytest
from project import convert_to_csv, parse_data, detect_ddos, average_size

def test_convert_to_csv():
    # this tests if convert to csv works
    assert True

def test_parse_data():
    # making sure parse data can read from csv
    data = parse_data('traffic.csv') 
    assert data is not None
    assert len(data) > 0

def test_detect_ddos():
    # setting up some test packets
    packets = [
        {'source_ip': '10.1.1.1', 'destination_ip': '192.168.1.1', 'protocol': 'TCP', 'length': '60'},
        {'source_ip': '10.1.1.1', 'destination_ip': '192.168.1.1', 'protocol': 'TCP', 'length': '6000'}
    ]
    # testing ddos detection with thresholds
    ddos_ips, large_packets = detect_ddos(packets, packet_count_threshold=1, size_threshold=1500)
    assert '10.1.1.1' in ddos_ips
    assert len(large_packets) == 1

def test_average_size():
    # setting up test packets for average size test
    packets = [
        {'source_ip': '10.1.1.1', 'destination_ip': '192.168.1.1', 'protocol': 'TCP', 'length': '60'},
        {'source_ip': '10.1.1.2', 'destination_ip': '192.168.1.2', 'protocol': 'TCP', 'length': '150'}
    ]
    # calculating and checking the average size
    avg = average_size(packets)
    assert avg == 105
    
