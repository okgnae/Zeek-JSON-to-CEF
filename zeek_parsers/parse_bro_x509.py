from datetime import datetime

def parse_bro_x509(msg_json):
    cef_headers = 'CEF:1|Security Onion|Zeek|1|bro_x509|Bro x509 Log|Low| '
    end_time = ''
    request_cookies = ''
    flex_number1 = ''
    custom_string1 = ''
    custom_string2 = ''
    custom_string3 = ''
    custom_string4 = ''
    custom_string5 = ''
    custom_string6 = ''
    custom_date1 = ''
    custom_date2 = ''
    flex_string1 = ''
    flex_string2 = ''
    fileType = ''
    fsize = ''

    for key, val in msg_json.get('Message').items():
        if key == 'ts':
            val = int(datetime.strptime(val.split('.')[0],"%Y-%m-%dT%H:%M:%S").timestamp() * 1000)
            end_time = f"end={val} "
        elif key == 'id':
            request_cookies = f"requestCookies={val} "
        elif key == 'certificate.version':
            flex_number1 = f"flexNumber1={val} "
        elif key == 'certificate.serial':
            custom_string1 = f"cs1={val} "
        elif key == 'certificate.subject':
            custom_string2 = f"cs2={val} "
        elif key == 'certificate.issuer':
            custom_string3 = f"cs3={val} "
        elif key == 'certificate.key_alg':
            custom_string4 = f"cs4={val} "
        elif key == 'certificate.sig_alg':
            custom_string5 = f"cs5={val} "
        elif key == 'san.ip':
            custom_string6 = f"cs6={val} "
        elif key == 'certificate.not_valid_before':
            val = int(datetime.strptime(val.split('.')[0],"%Y-%m-%dT%H:%M:%S").timestamp() * 1000)
            custom_date1 = f"deviceCustomDate1={val} "
        elif key == 'certificate.not_valid_after':
            val = int(datetime.strptime(val.split('.')[0],"%Y-%m-%dT%H:%M:%S").timestamp() * 1000)
            custom_date2 = f"deviceCustomDate2={val} "
        elif key == 'certificate.exponent':
            flex_string1 = f"flexString1={val} "
        elif key == 'basic_constraints.ca':
            flex_string2 = f"flexString2={val} "

    return ''.join((
        cef_headers,
        end_time,
        request_cookies,
        flex_number1,
        'flexNumber1Label=certificate.version ',
        custom_string1,
        'cs1Label=certificate.serial ',
        custom_string2,
        'cs2Label=certificate.subject ',
        custom_string3,
        'cs3Label=certificate.issuer ',
        custom_string4,
        'cs4Label=certificate.key_alg ',
        custom_string5,
        'cs5Label=certificate.sig_alg ',
        custom_string6,
        'cs6Label=san.ip ',
        custom_date1,
        'deviceCustomDate1Label=certificate.not_valid_before ',
        custom_date2,
        'deviceCustomDate2Label=certificate.not_valid_after ',
        flex_string1,
        'flexString1Label=certificate.exponent ',
        flex_string2,
        'flexString2Label=basic_constraints.ca ',
        fileType,
        fsize,
    ))
