import socket
from datetime import datetime

def parse_bro_conn(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_conn|Bro Connection Log|Low| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    destination_service_name = ''
    transport_protocol = ''
    custom_string5 = ''
    bytes_in = ''
    bytes_out = ''
    custom_string1 = ''
    flex_string1 = ''
    flex_string2 = ''
    custom_number1 = ''
    custom_string2 = ''
    custom_string3 = ''
    flex_number1 = ''
    custom_string4 = ''
    flex_number2 = ''
    device_hostname = ''
    custom_string6 = ''
    custom_number2 = ''
    custom_number3 = ''
    source_Hostname = ''
    destination_Hostname = ''

    for key, val in msg_json.get('Message').items():
        if key == 'ts':
            val = int(datetime.strptime(val.split('.')[0],"%Y-%m-%dT%H:%M:%S").timestamp() * 1000)
            end_time = f"end={val} "
        elif key == 'uid':
            request_cookies = f"requestCookies={val} "
        elif key == 'id.orig_h':
            source_address = f"src={val} "
            source_Hostname = f"shost={socket.gethostbyaddr(val)[0]} "
        elif key == 'id.orig_p':
            source_port = f"spt={val} "
        elif key == 'id.resp_h':
            destination_address = f"dst={val} "
            destination_Hostname = f"dhost={socket.gethostbyaddr(val)[0]} "
        elif key == 'id.resp_p':
            destination_port = f"dpt={val} "
        elif key == 'proto':
            transport_protocol = f"proto={val} "
        elif key == 'service':
            destination_service_name = f"destinationServiceName={val} "
        elif key == 'duration':
            custom_string5 = f"cs5={val} "
        elif key == 'orig_bytes':
            bytes_in = f"in={val} "
        elif key == 'resp_bytes':
            bytes_out = f"out={val} "
        elif key == 'conn_state':
            custom_string1 = f"cs1={val} "
        elif key == 'local_orig':
            flex_string1 = f"flexString1={val} "
        elif key == 'local_resp':
            flex_string2 = f"flexString2={val} "
        elif key == 'missed_bytes':
            custom_number3 = f"cn3={val} "
        elif key == 'history':
            custom_string2 = f"cs2={val} "
        elif key == 'orig_pkts':
            custom_string3 = f"cs3={val} "
        elif key == 'orig_ip_bytes':
            custom_number1 = f"cn1={val} "
        elif key == 'resp_pkts':
            custom_string4 = f"cs4={val} "
        elif key == 'resp_ip_bytes':
            custom_number2 = f"cn2={val} "
        elif key == 'sensorname':
            device_hostname = f"dvchost={val} "

    return ''.join((
        cef_headers,
        end_time,
        source_address,
        source_Hostname,
        source_port,
        destination_address,
        destination_Hostname,
        destination_port,
        destination_service_name,
        bytes_in,
        bytes_out,
        flex_string1,
        'flexString1Label=local_orig ',
        flex_string2,
        'flexString2Label=local_resp ',
        custom_string1,
        'cs1Label=conn_state ',
        custom_string2,
        'cs2Label=history ',
        custom_string3,
        'cs3Label=orig_pkts ',
        custom_string4,
        'cs4Label=resp_pkts ',
        custom_string5,
        'cs5Label=duration ',
        custom_string6,
        'cs6Label=uid ',
        custom_number1,
        'cn1Label=orig_ip_bytes ',
        custom_number2,
        'cn2Label=resp_ip_bytes ',
        custom_number3,
        'cn3Label=missed_bytes ',
        device_hostname
    ))
