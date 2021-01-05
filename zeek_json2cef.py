from confluent_kafka import Consumer, Producer
import datetime
import json
import logging
import logging.handlers
import zeek_parsers
import os
import signal

# main function enabled var
running = True

# Logging vars
logging_file_path = '/opt/confluent-kafka-python/log/zeek_parser.log'
logging_mode = 'a'
logging_max_bytes = 1000000
logging_backup_file_count = 9

def recv_sig_term(signal_number, frame):
    global running
    running = False

def enable_logging(logging_file_path, logging_mode, logging_max_bytes, logging_backup_file_count):
    handler = logging.handlers.RotatingFileHandler(
        filename=logging_file_path,
        mode=logging_mode,
        maxBytes=logging_max_bytes,
        backupCount=logging_backup_file_count,
    )

    handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger

def init_kafka_consumer():
    kc = Consumer({
        'bootstrap.servers': 'k01:9093, k02:9093, k03:9093',
        'ssl.ca.location': '/opt/confluent-kafka-python/cacert.pem',
        'security.protocol': 'ssl',
        'group.id': 'zeek_json',
    })
    kc.subscribe(['ZEEK'])
    return kc

def init_kafka_producer():
    kp = Producer({
        'bootstrap.servers': 'k01:9093, k02:9093, k03:9093',
        'ssl.ca.location':'/opt/confluent-kafka-python/cacert.pem',
        'security.protocol':'ssl',
        'client.id': 'Zeekjson2cef',
    })
    return kp

def load_zeek_parsers():
    return {
        'bro_conn': zeek_parsers.parse_bro_conn,
        'bro_dns': zeek_parsers.parse_bro_dns,
        'bro_rdp': zeek_parsers.parse_bro_rdp,
        'bro_dce_rpc': zeek_parsers.parse_bro_dce_rpc,
        'bro_weird': zeek_parsers.parse_bro_weird,
        'bro_x509': zeek_parsers.parse_bro_x509,
        'bro_ftp': zeek_parsers.parse_bro_ftp,
        'bro_smb_files': zeek_parsers.parse_bro_smb_files,
        'bro_ssl': zeek_parsers.parse_bro_ssl,
        'bro_notice': zeek_parsers.parse_bro_notice,
        'bro_ntlm': zeek_parsers.parse_bro_ntlm,
        'bro_files': zeek_parsers.parse_bro_files,
        'bro_snmp': zeek_parsers.parse_bro_snmp,
        'bro_kerberos': zeek_parsers.parse_bro_kerberos,
        'bro_smb_mapping': zeek_parsers.parse_bro_smb_mapping,
        'bro_http': zeek_parsers.parse_bro_http,
    }

def main():
    logger = enable_logging(logging_file_path, logging_mode, logging_max_bytes, logging_backup_file_count)
    logger.info('Zeek Parser Service Started')
    logger.info(f"Zeek Parser Service Running with PID {os.getpid()}")

    signal.signal(signal.SIGTERM, recv_sig_term)
    signal.signal(signal.SIGINT, recv_sig_term)

    logger.info('Loading Zeek Parsers')
    parser_dict = load_zeek_parsers()
    logger.info(f"Zeek Parsers loaded {[key for key in parser_dict.keys()]}")

    logger.info('Initilizing Kafka Consumer')
    kc = init_kafka_consumer()

    logger.info('Initilizing Kafka Producer')
    kp = init_kafka_producer()

    event_count = 0
    event_endtime = datetime.datetime.now() + datetime.timedelta(0,60)
    
    logger.info('Start message processing')
    while running:
        msg = kc.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            continue

        event_count += 1
        if event_endtime <= datetime.datetime.now():
            logger.info(f"Zeek Parser EPS={event_count / 60}")
            event_count = 0
            event_endtime = datetime.datetime.now() + datetime.timedelta(0,60)

        try:
            msg_json = json.loads(msg.value().decode('utf-8'))
        except:
            logger.error(f"json.loads failed - {msg.value().decode('utf-8')}")
            continue

        try:
            kp.produce('ZEEK_CEF', parser_dict[msg_json.get('LogType')](msg_json))
            kp.poll(0)
        except:
            logger.debug(f"no parser found - {msg_json}")
            continue

    kc.close()
    logger.info('Zeek Parser Service Stopped')


if __name__ == '__main__':
    main()
