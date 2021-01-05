import socket
from datetime import datetime

def parse_bro_http(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_http|Bro HTTP Log|HIGH| '
    end_time = ''
    request_cookies = ''
    source_address = ''
    source_port = ''
    destination_address = ''
    destination_port = ''
    generator_name = ''
    request_Method = ''
    request_Url_Host = ''
    generator_Uri = ''
    generator_Resource = ''
    generator_Id = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    custom_string4 = ''
    custom_string5 = ''
    custom_string6 = ''
    request_Context = ''
    request_Url_Query = ''
    request_Url = ''
    flex_string1 = ''
    flex_string2 = ''
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
        elif key == 'trans_depth':
            generator_name = f"trans_depth={val} "
        elif key == 'method':
            request_Method = f"method={val} "
        elif key == 'host':
            request_Url_Host = f"host={val} "
        elif key == 'uri':
            generator_Uri = f"uri={val} "
        elif key == 'referrer':
            generator_Resource = f"referrer={val} "
        elif key == 'vesion':
            generator_Id = f"version={val} "
        elif key == 'user_agent':
            custom_string1 = f"cs1={val} "
        elif key == 'origin':
            custom_string2 = f"cs2={val} "
        elif key == 'request_body_len':
            custom_string3 = f"cs3={val} "
        elif key == 'response_body_len':
            custom_string4 = f"cs4={val} "
        elif key == 'status_code':
            custom_string5 = f"cs5={val} "
        elif key == 'status_msg':
            custom_string6 = f"cs6={val} "
        elif key == 'info_code':
            request_Context = f"info_code={val} "
        elif key == 'info_msg':
            request_Url_Query = f"info_msg={val} "
        elif key == 'tags':
            request_Url = f"tags={val} "
        elif key == 'username':
            flex_string1 = f"flexString1={val} "
        elif key == 'password':
            flex_string2 = f"flexString2={val} "

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
