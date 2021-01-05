import socket
from datetime import datetime

def parse_bro_rdp(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_rdp|Bro RDP Log|Low| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    custom_string4 = ''
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
        elif key == 'cookie':
            custom_string1 = f"cs1={val} "
        elif key == 'result':
            custom_string2 = f"cs2={val} "
        elif key == 'security_protocol':
            custom_string3 = f"cs3={val} "
        elif key == 'cert_count':
            custom_string4 = f"cs4={val} "

    return ''.join((
        cef_headers,
        end_time,
        request_cookies,
        source_address,
        source_port,
        destination_address,
        destination_port,
        custom_string1,
        'cs1Label=RDPUser ',
        custom_string2,
        'cs2Label=Result ',
        custom_string3,
        'cs3Label=SecurityProtocol ',
        custom_string4,
        'cs4Label=CertificateCount ',
        source_Hostname,
        destination_Hostname
    ))
