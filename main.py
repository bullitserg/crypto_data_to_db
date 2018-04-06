import ets.ets_certmanager_logs_parser as parser
import argparse
import logger_module
from datetime import datetime
from ets.ets_mysql_lib import MysqlConnection as mc, NULL, value_former
import ets.ets_certificate_lib as crt_lib
from os.path import normpath, join
from queries import *
from config import *

PROGNAME = 'Crypto data to bd parser'
DESCRIPTION = '''Скрипт для импорта данных из файлов криптоменеджера в базу данных'''
VERSION = '1.0'
AUTHOR = 'Belim S.'
RELEASE_DATE = '2018-03-30'

type_by_number = {1: 'mroot', 2: 'mca', 3: 'crl'}

tmp_dir = normpath(tmp_dir)
d_server_list = 1, 2, 4, 5
d_storage_list = 'mroot', 'mca', 'crl'
d_storage_numbers = range(1, 4)
d_days = 10
d_insert_datetime = datetime.now()

u_server_list = []
u_storage_list = []


def show_version():
    print(PROGNAME, VERSION, '\n', DESCRIPTION, '\nAuthor:', AUTHOR, '\nRelease date:', RELEASE_DATE)


# обработчик параметров командной строки
def create_parser():
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-v', '--version', action='store_true',
                        help="Show version")

    parser.add_argument('-u', '--update', action='store_true',
                        help="Update records in database for server and file.  Others: --server, --file, --number")

    parser.add_argument('-f', '--fast_update_by_auth_key', action='store_true',
                        help="Fast update records in database by auth_key. Must set --auth_key, others: --server")

    parser.add_argument('-r', '--remove', action='store_true',
                        help="Delete old records from database for server. Others: --server, --days")

    parser.add_argument('-s', '--server', type=int, choices=d_server_list,
                        help="Set server number")

    parser.add_argument('-i', '--file', type=str, choices=d_storage_list,
                        help="Set storage file")

    parser.add_argument('-k', '--auth_key', type=str,
                        help="Set auth_key")

    parser.add_argument('-n', '--number', type=int, choices=d_storage_numbers,
                        help="Set storage number")

    parser.add_argument('-d', '--days', type=int,
                        help="Set days count")

    return parser


def insert_worker(server, storage, **kwargs):

    auth_key = kwargs.get('auth_key')

    types = {'mroot': {'file': 'mRoot_%s.txt' % server, 'storage_num': 1},
             'mca': {'file': 'mCA_%s.txt' % server, 'storage_num': 2},
             'crl': {'file': 'CRL_%s.txt' % server, 'storage_num': 3}}

    # создаем подключение к нужной бд
    cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
    cn.connect()

    def insert_by_key(c_key):
        d_insert = c_info.get(c_key, None)

        if not d_insert:
            print('Auth_key не найден')
            return

        # добавляем недостающие ключи в случае их отсутствия
        for key in check_keys:
            if key not in d_insert:
                d_insert[key] = NULL
            d_insert[key] = value_former(d_insert[key])

        # добавляем оставшиеся поля поля
        d_insert['storage_num'] = value_former(types[storage]['storage_num'])
        d_insert['storage_name'] = value_former(storage)
        d_insert['server'] = value_former(server)
        d_insert['datetime'] = value_former(d_insert_datetime)

        cn.execute_query(insert_query % d_insert)

    print('Обработка хранилища %s сервера %s' % (storage, server))

    f = join(tmp_dir, types[storage]['file'])

    c_f = parser.CertmanagerFile(f, timezone=3)
    c_file_type = c_f.file_type
    if c_file_type == 'CERT':
        c_info = c_f.get_info(key='SubjKeyID')
    else:
        c_info = c_f.get_info(key='AuthKeyID')

    # в зависимости от типа обрабатываемого файла нужно предопределить некоторый набор ключей
    # а так же определить запросы для добавления и удаления данных
    if c_file_type == 'CERT':
            check_keys = ('OrderNum', 'Serial', 'SubjKeyID', 'Issuer', 'Subject', 'Not valid before', 'Not valid after',
                          'PrivateKey Link', 'PublicKey Algorithm', 'Signature Algorithm', 'SHA1 Hash')
            insert_query = certificate_data_insert_query
    else:
        check_keys = ('OrderNum', 'Issuer', 'AuthKeyID', 'NextUpdate', 'ThisUpdate')
        insert_query = crl_data_insert_query

    # если указан auth_key, то обрабатываем только по нему
    if auth_key:
        auth_key = auth_key.replace(' ', '')
        insert_by_key(auth_key)
    else:
        for a_key in c_info.keys():
            insert_by_key(a_key)

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
            u_storage_list.append(namespace.file)
        elif namespace.number:
            u_storage_list.append(type_by_number[namespace.number])
        else:
            u_storage_list = d_storage_list

        if namespace.remove:
            cn = mc(connection=mc.MS_CERT_INFO_CONNECT)
            cn.connect()
            if namespace.server:
                u_server_list.append(namespace.server)
            else:
                u_server_list = d_server_list

            if namespace.days:
                day = namespace.days
            else:
                day = d_days

            for server in u_server_list:
                cn.execute_query(certificate_data_delete_query, day, server)
                cn.execute_query(crl_data_delete_query, day, server)

            print('Сведения за %s дней удалены' % day)
            cn.disconnect()
            exit(0)

        if namespace.update:
            for server in u_server_list:
                print('Получение данных сервера %s' % server)
                parser.get_info_file(server, out_dir=tmp_dir)
                for storage in u_storage_list:
                    insert_worker(server, storage)
            exit(0)

        if namespace.fast_update_by_auth_key:
            for server in u_server_list:
                print('Получение данных сервера %s' % server)
                parser.get_info_file(server, out_dir=tmp_dir)

                if not namespace.auth_key:
                    print('Укажите auth_key')
                    exit(0)

                for storage in u_storage_list:
                    insert_worker(server, storage, auth_key=namespace.auth_key)

                print('Сведения по auth_key "%s" обновлены' % namespace.auth_key)
                exit(0)

        show_version()
        print('For more information run use --help')

    # если при исполнении будут исключения - кратко выводим на терминал, остальное - в лог
    except Exception as e:
        logger.fatal('Fatal error! Exit', exc_info=True)
        print('Critical error: %s' % e)
        print('More information in log file')
        exit(1)

    exit(0)



