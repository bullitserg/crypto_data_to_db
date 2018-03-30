import ets.ets_certmanager_logs_parser as parser
import argparse
import logger_module
from datetime import datetime
from ets.ets_mysql_lib import MysqlConnection as mc
from os.path import normpath, join
from queries import *
from config import *

PROGNAME = 'Crypto data to bd parser'
DESCRIPTION = '''Скрипт для импорта данных из файлов криптоменеджера в базу данных'''
VERSION = '1.0'
AUTHOR = 'Belim S.'
RELEASE_DATE = '2018-03-30'

types = {'mroot': {'file': 'mRoot_list.txt', 'storage_num': 1},
         'mca': {'file': 'mCA_list.txt', 'storage_num': 2},
         'crl': {'file': 'CRL_list.txt', 'storage_num': 3}}

type_by_number = {1: 'mroot', 2: 'mca', 3: 'crl'}

tmp_dir = normpath(tmp_dir)
d_server_list = 1, 2, 4, 5
d_storage_list = 'mroot', 'mca', 'crl'
d_storage_numbers = range(1, 4)
d_insert_datetime = datetime.now()

u_server_list = []
u_storage_list = []
delete = True


def show_version():
    print(PROGNAME, VERSION, '\n', DESCRIPTION, '\nAuthor:', AUTHOR, '\nRelease date:', RELEASE_DATE)


# обработчик параметров командной строки
def create_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-v', '--version', action='store_true',
                        help="Show version")

    parser.add_argument('-s', '--server', type=int, choices=d_server_list,
                        help="Set server number")

    parser.add_argument('-f', '--file', type=str, choices=d_storage_list,
                        help="Set storage file")

    parser.add_argument('-n', '--number', type=int, choices=d_storage_numbers,
                        help="Set storage number")

    parser.add_argument('-d', '--delete', action='store_true',
                        help="Delete old records from database for server and file")

    parser.add_argument('-u', '--update', action='store_true',
                        help="Update records in database for server and file")

    return parser


def insert_worker(server, storage):
    # создаем подключение к нужной бд
    cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
    cn.connect()

    print('Получение данных сервера %s' % server)
    parser.get_info_file(server, out_dir=tmp_dir)

    print('Обработка хранилища %s сервера %s' % (storage, server))

    f = join(tmp_dir, types[storage]['file'])

    c_f = parser.CertmanagerFile(f, timezone=3)
    c_file_type = c_f.file_type
    c_info = c_f.get_info(key='OrderNum')

    # в зависимости от типа обрабатываемого файла нужно предопределить некоторый набор ключей
    # а так же определить запросы для добавления и удаления данных
    if c_file_type == 'CERT':
            check_keys = ('OrderNum', 'Serial', 'SubjKeyID', 'Issuer', 'Subject', 'Not valid before', 'Not valid after',
                          'PrivateKey Link', 'PublicKey Algorithm', 'Signature Algorithm', 'SHA1 Hash')
            insert_query = certificate_data_insert_query
            if delete:
                cn.execute_query(certificate_data_delete_query, server, types[storage]['storage_num'])
    else:
        check_keys = ('OrderNum', 'Issuer', 'AuthKeyID', 'NextUpdate', 'ThisUpdate')
        insert_query = crl_data_insert_query
        if delete:
            cn.execute_query(crl_data_delete_query, server)

    # добавляем недостающие ключи в случае их отсутствия
    for cert_key in sorted(c_info.keys()):
        d_insert = c_info[cert_key]
        for key in check_keys:
            if key not in d_insert:
                d_insert = ""

        # дополнительно у сертификата нужно заэкранировать
        if c_file_type == 'CERT':
            for key in ('Issuer', 'Subject'):
                d_insert[key] = d_insert[key].replace("'", "\\'")

        # добавляем оставшиеся поля поля
        d_insert['storage_num'] = types[storage]['storage_num']
        d_insert['storage_name'] = storage
        d_insert['server'] = server
        d_insert['datetime'] = d_insert_datetime

        cn.execute_query(insert_query % d_insert)

    cn.disconnect()


# ОСНОВНОЙ КОД
if __name__ == '__main__':

    logger = logger_module.logger()
    try:
        # парсим аргументы командной строки
        my_parser = create_parser()
        namespace = my_parser.parse_args()

        if namespace.version:
            show_version()
            exit(0)

        if namespace.server:
            u_server_list.append(namespace.server)
        else:
            u_server_list = d_server_list

        if namespace.file:
            u_storage_list.append(namespace.server)
        else:
            u_storage_list = d_storage_list

        if namespace.number:
            u_storage_list.append(type_by_number[namespace.number])
        else:
            u_storage_list = d_storage_list

        # на тот случай, если объявлен и namespace.file и namespace.number - удалим дубликаты
        u_storage_list = set(u_storage_list)

        if namespace.delete:
            delete = True

        if namespace.update:
            for server in u_server_list:
                for storage in u_storage_list:
                    insert_worker(server, storage)

        else:
            show_version()
            print('For more information run use --help')

    # если при исполнении будут исключения - кратко выводим на терминал, остальное - в лог
    except Exception as e:
        logger.fatal('Fatal error! Exit', exc_info=True)
        print('Critical error: %s' % e)
        print('More information in log file')
        exit(1)

    exit(0)



