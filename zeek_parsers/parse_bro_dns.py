import socket
from datetime import datetime

def parse_bro_dns(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_dns|Bro DNS Log|Low| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    transport_protocol = ''
    custom_number1 = ''
    custom_number2 = ''
    flexString1 = ''
    flexString2 = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    custom_string4 = ''
    custom_string5 = ''
    custom_string6 = ''
    request_url = ''
    request_context = ''
    request_method = ''
    act = ''
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
        elif key == 'trans_id':
            custom_number1 = f"cn1={val} "
        elif key == 'Z':
            custom_number2 = f"cn2={val} "
        elif key == 'query':
            request_url = f"request={val} "
        elif key == 'qclass_name':
            request_context = f"requestContext={val} "
        elif key == 'qtype_name':
            request_method = f"requestMethod={val} "
        elif key == 'rcode_name':
            act = f"act={val} "
        elif key == 'AA':
            flex_string1 = f"flexString1={val} "
        elif key == 'TC':
            flex_string2 = f"flexString2={val} "
        elif key == 'rtt':
            custom_string1 = f"cs1={val} "
        elif key == 'RD':
            custom_string2 = f"cs2={val} "
        elif key == 'RA':
            custom_string3 = f"cs3={val} "
        elif key == 'answers':
            custom_string4 = f"cs4={val} "
        elif key == 'TTLs':
            custom_string5 = f"cs5={val} "
        elif key == 'rejected':
            custom_string6 = f"cs6={val} "

    return ''.join((
        cef_headers,
        end_time,
        request_cookies,
        source_address,
        source_port,
        destination_address,
        destination_port,
        transport_protocol,
        custom_number1,
        'cn1Label=trans_id ',
        custom_number2,
        'cn2Label=Z ',
        flexString1,
        'flexString1Label=AA ',
        flexString2,
        'flexString2Label=TC ',
        custom_string1,
        'cs1Label=rtt ',
        custom_string2,
        'cs2Label=RD ',
        custom_string3,
        'cs3Label=RA ',
        custom_string4,
        'cs4Label=answers ',
        custom_string5,
        'cs5Label=TTLs ',
        custom_string6,
        'cs6Label=rejected ',
        request_url,
        request_context,
        request_method,
        act,
        source_Hostname,
        destination_Hostname
    ))
