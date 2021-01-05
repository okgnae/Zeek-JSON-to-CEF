import socket
from datetime import datetime

def parse_bro_ssl(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_ssl|Bro SSL Log|Low| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    transport_protocol = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    custom_string4 = ''
    custom_string5 = ''
    custom_string6 = ''
    flex_string1 = ''
    flex_string2 = ''
    request_Url = ''
    request_Context = ''
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
        elif key == 'version':
            transport_protocol = f"proto={val} "
        elif key == 'cipher':
            custom_string1 = f"cs1={val} "
        elif key == 'curve':
            custom_string2 = f"cs2={val} "
        elif key == 'server_name':
            custom_string3 = f"cs3={val} "
        elif key == 'resumed':
            custom_string4 = f"cs4={val} "
        elif key == 'established':
            custom_string5 = f"cs5={val} "
        elif key == 'cert_chain_fuids':
            custom_string6 = f"cs6={val} "
        elif key == 'client_cert_chain_fuid':
            flex_string1 = f"flexString1={val} "
        elif key == 'subject':
            flex_string2 = f"flexString2={val} "
        elif key == 'ja3':
            request_Url = f"ja3={val} "
        elif key == 'ja3s':
            request_Context = f"ja3s={val} "

    return ''.join((
        cef_headers,
        end_time,
        request_cookies,
        source_address,
        source_port,
        destination_address,
        destination_port,
        transport_protocol,
        custom_string1,
        'cs1Label=cipher ',
        custom_string2,
        'cs2Label=curve ',
        custom_string3,
        'cs3Label=Server Name ',
        custom_string4,
        'cs4Label=resumed ',
        custom_string5,
        'cs5Label=established ',
        custom_string6,
        'cs6Label=cert chain fuid ',
        flex_string1,
        'flexString1Label=client cert chain fuid ',
        flex_string2,
        'flexString2Label=Subject ',
        request_Url,
        request_Context,
        source_Hostname,
        destination_Hostname
    ))
