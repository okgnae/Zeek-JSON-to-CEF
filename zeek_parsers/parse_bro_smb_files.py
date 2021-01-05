import socket
from datetime import datetime

def parse_bro_smb_files(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_smb_files|Bro SMB Files Log|LOW| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    file_size = ''
    source_Hostname = ''
    destination_Hostname = ''

    for key, val in msg_json.get('Message').items():
        if key == 'ts':
            end_time = f"end={int(datetime.strptime(val.split('.')[0],"%Y-%m-%dT%H:%M:%S").timestamp() * 1000)} "
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
        elif key == 'action':
            custom_string1 = f"cs1={val} "
        elif key == 'path':
            custom_string2 = f"cs2={val} "
        elif key == 'name':
            custom_string3 = f"\{val} "
        elif key == 'size':
            file_size = f"cn1={val} "

    custom_string2 = custom_string2 + custom_string3

    return ''.join((
        cef_headers,
        end_time,
        request_cookies,
        source_address,
        source_port,
        destination_address,
        destination_port,
        custom_string1,
        'cs1Label=File Action ',
        custom_string2,
        'cs2Label=File Path ',
        file_size,
        'cn1Label=File Size ',
        source_Hostname,
        destination_Hostname
    ))
