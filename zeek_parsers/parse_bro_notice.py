import socket
from datetime import datetime

def parse_bro_notice(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_notice|Bro Notice Log|Low| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    generator_Name = ''
    transport_protocol = ''
    flexString1 = ''
    flexString2 = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    custom_string4 = ''
    custom_string5 = ''
    custom_string6 = ''
    custom_number1 = ''
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
        elif key == 'fuid':
            generator_Name = f"fuid={val} "
        elif key == 'proto':
            transport_protocol = f"proto={val} "
        elif key == 'note':
            flex_string1 = f"flexString1={val} "
        elif key == 'msg':
            flex_string2 = f"flexString2={val} "
        elif key == 'sub':
            custom_string1 = f"cs1={val} "
        elif key == 'src':
            custom_string2 = f"cs2={val} "
        elif key == 'dst':
            custom_string3 = f"cs3={val} "
        elif key == 'p':
            custom_string4 = f"cs4={val} "
        elif key == 'peer_descr':
            custom_string5 = f"cs5={val} "
        elif key == 'actions':
            custom_string6 = f"cs6={val} "
        elif key == 'suppress_for':
            custom_number1 = f"cn1={val} "

    return ''.join((
        cef_headers,
        end_time,
        request_cookies,
        source_address,
        source_port,
        destination_address,
        destination_port,
        generator_Name,
        transport_protocol,
        flexString1,
        'flexString1Label=note ',
        flexString2,
        'flexString2Label=msg ',
        custom_string1,
        'cs1Label=sub ',
        custom_string2,
        'cs2Label=source ',
        custom_string3,
        'cs3Label=destination ',
        custom_string4,
        'cs4Label=port ',
        custom_string5,
        'cs5Label=peer_descr ',
        custom_string6,
        'cs6Label=actions ',
        custom_number1,
        'cn1Label=suppress_for ',
        source_Hostname,
        destination_Hostname
    ))
