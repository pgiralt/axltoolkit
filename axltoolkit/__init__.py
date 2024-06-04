from zeep import Client
from zeep.cache import SqliteCache
from zeep.transports import Transport
from zeep.plugins import HistoryPlugin
from requests import Session
from requests.auth import HTTPBasicAuth
import urllib3
import logging.config
import logging
import os
from lxml.etree import tostring
from pathlib import Path
import tempfile
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def enable_logging():
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class AxlToolkit:

    wsdl = ""
    last_exception = None
    history = HistoryPlugin()

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, version='12.5', tls_verify=True, timeout=10, logging_enabled=False):
        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify
        filedir = os.path.dirname(__file__)

        self.cache = SqliteCache(path=Path(tempfile.gettempdir()+'/sqlite_{0}.db'.format(server_ip)), timeout=60)

        if version == '12.5':
            self.wsdl = os.path.join(filedir, 'schema/12.5/AXLAPI.wsdl')
        elif version == '12.0':
            self.wsdl = os.path.join(filedir, 'schema/12.0/AXLAPI.wsdl')
        elif version == '11.5':
            self.wsdl = os.path.join(filedir, 'schema/11.5/AXLAPI.wsdl')
        elif version == '11.0':
            self.wsdl = os.path.join(filedir, 'schema/11.0/AXLAPI.wsdl')
        elif version == '10.5':
            self.wsdl = os.path.join(filedir, 'schema/10.5/AXLAPI.wsdl')
        elif version == '10.0':
            self.wsdl = os.path.join(filedir, 'schema/10.0/AXLAPI.wsdl')
        else:
            self.wsdl = os.path.join(filedir, 'schema/12.5/AXLAPI.wsdl')

        self.client = Client(wsdl=self.wsdl, plugins=[self.history], transport=Transport(timeout=timeout,
                                                                                         operation_timeout=timeout,
                                                                                         cache=self.cache,
                                                                                         session=self.session))

        self.service = self.client.create_service("{http://www.cisco.com/AXLAPIService/}AXLAPIBinding",
                                                  "https://{0}:8443/axl/".format(server_ip))

        if logging_enabled:
            enable_logging()

    def get_service(self):
        return self.service

    def last_request_debug(self):
        request_env = tostring(self.history.last_sent['envelope'])
        request_headers = self.history.last_sent['http_headers']
        response_env = tostring(self.history.last_received['envelope'])
        response_headers = self.history.last_received['http_headers']

        return {
            'request': {
                'raw': self.history.last_sent,
                'headers': request_headers,
                'envelope': request_env
            },
            'response': {
                'raw': self.history.last_received,
                'headers': response_headers,
                'envelope': response_env

            }
         }



    '''
    
    Thin AXL (SQL Queries / Updates)
    
    '''

    def run_sql_query(self, query):
        result = {'num_rows': 0,
                  'query': query}

        try:
            sql_result = self.service.executeSQLQuery(sql=query)
        except Exception as fault:
            sql_result = None
            self.last_exception = fault

        num_rows = 0
        result_rows = []

        if sql_result is not None:
            if sql_result['return'] is not None:
                for row in sql_result['return']['row']:
                    result_rows.append({})
                    for column in row:
                        result_rows[num_rows][column.tag] = column.text
                    num_rows += 1

        result['num_rows'] = num_rows
        if num_rows > 0:
            result['rows'] = result_rows

        return result


    def run_sql_update(self, query):
        result = {'rows_updated': 0,
                  'query': query}

        try:
            sql_result = self.service.executeSQLUpdate(sql=query)
        except Exception as fault:
            sql_result = None
            self.last_exception = fault

        if sql_result is not None:
            if sql_result['return'] is not None:
                result['rows_updated'] = sql_result['return']['rowsUpdated']

        return result


    '''
    
    UCM Group
    
    '''

    def get_ucm_group(self, name):
        try:
            result = self.service.getCallManagerGroup(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_ucm_group_members(self, name, members):

        member_data = []
        member_count = 0

        for member in members:
            member_count += 1
            member_data.append({'priority': member_count, 'callManagerName': member})

        try:
            result = self.service.updateCallManagerGroup(name=name, members={'member': member_data})
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_ucm_group(self, name, members):

        member_data = []
        member_count = 0

        for member in members:
            member_count += 1
            member_data.append({'priority': member_count, 'callManagerName': member})

        try:
            result = self.service.addCallManagerGroup(callManagerGroup=
                                                      {'name': name, 'members':{'member': member_data}})
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_ucm_group(self, name):
        try:
            result = self.service.removeCallManagerGroup(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result


    '''
    
    Users
    
    '''

    def get_user(self, userid):
        try:
            result = self.service.getUser(userid=userid)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def list_users(self, **kwargs):

        allowed_tags = ['firstName', 'lastName', 'userid', 'department']
        search_criteria = {}
        users = {}

        if kwargs is not None:
            for key, value in kwargs.items():
                if key in allowed_tags:
                    search_criteria[key] = value

        if len(search_criteria) == 0:
            search_criteria['userid'] = '%'

        returned_tags = {'firstName': '', 'lastName': '', 'userid': ''}

        try:
            result = self.service.listUser(searchCriteria=search_criteria, returnedTags=returned_tags)

            if result['return'] is not None:

                for user in result['return']['user']:

                    users[user['userid']] = {}

                    users[user['userid']]['uuid'] = user['uuid']
                    users[user['userid']]['firstName'] = user['firstName']
                    users[user['userid']]['lastName'] = user['lastName']
                    users[user['userid']]['userid'] = user['userid']

        except Exception as fault:
            users = None
            self.last_exception = fault

        return users

    def update_user(self, user_data):
        try:
            result = self.service.updateUser(**user_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def sql_get_device_pkid(self, device):

        sql_query = "select pkid from device where name = '{0}'".format(device)

        result = self.run_sql_query(sql_query)

        if result['num_rows'] > 0:
            pkid = result['rows'][0]['pkid']
        else:
            pkid = None

        return pkid

    def sql_get_user_group_pkid(self, group_name):

        sql_query = "select pkid from dirgroup where name = '{0}'".format(group_name)

        result = self.run_sql_query(sql_query)

        if result['num_rows'] > 0:
            pkid = result['rows'][0]['pkid']
        else:
            pkid = None

        return pkid

    def sql_get_enduser_pkid(self, userid):

        sql_query = "select pkid from enduser where userid = '{0}'".format(userid)

        result = self.run_sql_query(sql_query)

        if result['num_rows'] > 0:
            pkid = result['rows'][0]['pkid']
        else:
            pkid = None

        return pkid

    def sql_associate_user_to_group(self, userid, group_name):

        user_group_pkid = self.sql_get_user_group_pkid(group_name)
        enduser_pkid = self.sql_get_enduser_pkid(userid)

        if user_group_pkid is not None and enduser_pkid is not None:
            query = "insert into enduserdirgroupmap (fkenduser, fkdirgroup) values ('{0}', '{1}')".format(enduser_pkid,
                                                                                                      user_group_pkid)

            sql_result = self.run_sql_update(query)

            if sql_result['rows_updated'] > 0:
                result = True
            else:
                result = False

            return result

    def sql_remove_user_from_group(self, userid, group_name):
        pass
        # TODO: Need to add this code

    '''
    
    Lines
    
    '''

    def get_line(self, dn, partition):
        try:
            result = self.service.getLine(pattern=dn, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_line(self, line_data):
        try:
            result = self.service.addLine(line=line_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_line(self, line_data):
        try:
            result = self.service.updateLine(**line_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''

    LDAP Filter 

    '''

    def get_ldap_filter(self, name):
        try:
            result = self.service.getLdapFilter(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_ldap_filter(self, name, filter_name):

        filter_data = {
            'name': name,
            'filter': filter_name
        }

        try:
            result = self.service.addLdapFilter(filter_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_ldap_filter(self, name):
        try:
            result = self.service.removeLdapFilter(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result


    '''
    
    LDAP Directory
    
    '''

    def get_ldap_directory(self, name):
        try:
            result = self.service.getLdapDirectory(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_ldap_directory(self, ldap_dir_data):

        try:
            result = self.service.addLdapDirectory(ldapDirectory=ldap_dir_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_ldap_directory(self, name):
        try:
            result = self.service.removeLdapDirectory(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def start_ldap_sync(self, ldap_name=None):
        query = "update directorypluginconfig set syncnow = '1'"
        if ldap_name is not None:
            query += "  where name = '{0}'".format(ldap_name)

        sql_result = self.run_sql_update(query)

        if sql_result['rows_updated'] > 0:
            result = True
        else:
            result = False

        return result

    ''' 
    
    LDAP System
    
    '''

    def get_ldap_system(self):
        try:
            result = self.service.getLdapSystem()
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_ldap_system(self, sync_enabled, ldap_server, user_id_attribute):

        try:
            result = self.service.updateLdapSystem(syncEnabled=sync_enabled,
                                                   ldapServer=ldap_server,
                                                   userIdAttribute=user_id_attribute)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result


    ''' 
    
    LDAP Authentication
    
    '''

    def get_ldap_authentication(self):
        try:
            result = self.service.getLdapAuthentication()
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_ldap_authentication(self, enabled, dn, password, search_base, servers, port, ssl):

        server_data = []

        for server in servers:
            server_data.append({'hostName': server,
                                'ldapPortNumber': port,
                                'sslEnabled': ssl})

        try:
            result = self.service.updateLdapAuthentication(authenticateEndUsers=enabled,
                                                           distinguishedName=dn,
                                                           ldapPassword=password,
                                                           userSearchBase=search_base,
                                                           servers={'server': server_data})
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''
    
    Phone
    
    '''

    def get_phone(self, name):
        try:
            result = self.service.getPhone(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_phone(self, phone_data, line_data=None):

        if line_data is not None:
            phone_data['lines'] = {'line': line_data}

        try:
            result = self.service.addPhone(phone=phone_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_phone(self, name):
        try:
            result = self.service.removePhone(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_phone(self, phone_data, line_data=None):

        if line_data is not None:
            phone_data['lines'] = {'line': line_data}

        try:
            result = self.service.updatePhone(**phone_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def list_phone(self, **kwargs):

        allowed_tags = ['name', 'description', 'protocol', 'callingSearchSpaceName', 'devicePoolName', 'securityProfileName']
        search_criteria = {}
        phones = {}

        if kwargs is not None:
            for key, value in kwargs.items():
                if key in allowed_tags:
                    search_criteria[key] = value

        if len(search_criteria) == 0:
            search_criteria['name'] = '%'

        returned_tags = {'name': '', 'description': '', 'devicePoolName': ''}

        try:
            print(search_criteria)
            print(returned_tags)

            result = self.service.listPhone(searchCriteria=search_criteria, returnedTags=returned_tags)

            if result['return'] is not None:

                for phone in result['return']['phone']:

                    phones[phone['name']] = {}

                    phones[phone['name']]['uuid'] = phone['uuid']
                    phones[phone['name']]['name'] = phone['name']
                    phones[phone['name']]['description'] = phone['description']
                    phones[phone['name']]['devicePoolName'] = phone['devicePoolName']

        except Exception as fault:
            phones = None
            self.last_exception = fault

        return phones



    '''
    
    Partitions
    
    '''

    def add_partition(self, name, description):

        partition_data = {'name': name,
                          'description': description}

        try:
            result = self.service.addRoutePartition(routePartition=partition_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    # Accepts a list of partitions, either as a list of strings with Partition names, or a list of dictionaries
    # containing the name and description for each partition.

    def add_partitions(self, partition_list):

        result = []

        for partition in partition_list:

            if not isinstance(partition, dict):
                partition = {"name": partition, "description": ""}

            try:
                result.append(self.service.addRoutePartition(routePartition=partition))
            except Exception as fault:
                result.append({'fault': fault})
                self.last_exception = fault

        return result

    def get_partition(self, name, returned_tags=None):

        try:
            if returned_tags is not None:
                result = self.service.getRoutePartition(name=name, returnedTags=returned_tags)
            else:
                result = self.service.getRoutePartition(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_partition(self, name):

        try:
            result = self.service.removeRoutePartition(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''
    
    Calling Search Space
    
    '''

    def add_css(self, name, description, partition_list):

        css_data = {'name': name,
                    'description': description,
                    'members':
                        {'member': []}
                    }

        css_index = 1
        for partition in partition_list:
            partition_data = {'routePartitionName': partition,
                              'index': css_index}
            css_data['members']['member'].append(partition_data)
            css_index += 1

        try:
            result = self.service.addCss(css=css_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def get_css(self, name):

        try:
            result = self.service.getCss(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_css(self, name):

        try:
            result = self.service.removeCss(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_css(self, css_name, description, partition_list):

        members = {'member': []}

        css_index = 1

        for partition in partition_list:
            partition_data = {'routePartitionName': partition,
                              'index': css_index}
            members['member'].append(partition_data)
            css_index += 1

        try:
            result = self.service.updateCss(name=css_name, description=description, members=members)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''

    Route Group

    '''

    def add_route_group(self, name, distribution_algorithm, device_list):

        rg_data = {
            'name': name,
            'distributionAlgorithm': distribution_algorithm,
            'members': {
                    'member': []
                }
            }

        rg_index = 1
        for device in device_list:
            rg_data['members']['member'].append({
                'deviceSelectionOrder': rg_index,
                'deviceName': device,
                'port': 0
            })
            rg_index += 1

        try:
            result = self.service.addRouteGroup(routeGroup=rg_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def get_route_group(self, name):

        try:
            result = self.service.getRouteGroup(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_route_group(self, name):

        try:
            result = self.service.removeRouteGroup(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_route_group(self, name):
        # TODO: Need to implement
        pass

    '''

    Route List

    '''

    def add_route_list(self, name, description, cm_group, enabled, roan, members, ddi=None):

        rl_data = {
            'name': name,
            'description': description,
            'callManagerGroupName': cm_group,
            'routeListEnabled': enabled,
            'runOnEveryNode': roan,
            'members': {
                    'member': []
                }
            }

        rg_index = 1
        for member in members:
            rl_data['members']['member'].append({
                'selectionOrder': rg_index,
                'routeGroupName': member,
                'digitDiscardInstructionName': ddi
            })
            rg_index += 1

        try:
            result = self.service.addRouteList(routeList=rl_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def get_route_list(self, name):

        try:
            result = self.service.getRouteList(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_route_list(self, name):

        try:
            result = self.service.removeRouteList(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_route_group(self, name):
        # TODO: Need to implement
        pass


    '''

    Route Pattern

    '''

    def add_route_pattern(self, pattern, partition, route_list, network_location, outside_dialtone):

        rp_data = {
            'pattern': pattern,
            'routePartitionName': partition,
            'destination': {
                    'routeListName': route_list
                },
            'blockEnable': False,
            'networkLocation': network_location,
            'provideOutsideDialtone': outside_dialtone
            }

        try:
            result = self.service.addRoutePattern(routePattern=rp_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def get_route_pattern(self, pattern, partition):

        try:
            result = self.service.getRoutePattern(pattern=pattern, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_route_pattern(self, pattern, partition):

        try:
            result = self.service.removeRoutePattern(pattern=pattern, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_route_pattern(self, name):
        # TODO: Need to implement
        pass

    '''

    Route Pattern

    '''

    def add_translation_pattern(self, pattern, partition, route_list, network_location, outside_dialtone):

        rp_data = {
            'pattern': pattern,
            'routePartitionName': partition,
            'blockEnable': False,
            'networkLocation': network_location,
            'provideOutsideDialtone': outside_dialtone
            }

        try:
            result = self.service.addRoutePattern(routePattern=rp_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def get_translation_pattern(self, pattern, partition):

        try:
            result = self.service.getRoutePattern(pattern=pattern, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_translation_pattern(self, pattern, partition):

        try:
            result = self.service.removeRoutePattern(pattern=pattern, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_translation_pattern(self, name):
        # TODO: Need to implement
        pass

    '''

    SIP Route Pattern

    '''

    def add_sip_route_pattern(self, pattern, partition, route_list):

        rp_data = {
            'pattern': pattern,
            'routePartitionName': partition,
            'sipTrunkName': route_list,
            'usage': 'Domain Routing',
            }

        try:
            result = self.service.addSipRoutePattern(sipRoutePattern=rp_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def get_sip_route_pattern(self, pattern, partition):

        try:
            result = self.service.getRoutePattern(pattern=pattern, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_sip_route_pattern(self, pattern, partition):

        try:
            result = self.service.removeRoutePattern(pattern=pattern, routePartitionName=partition)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_sip_route_pattern(self, name):
        # TODO: Need to implement
        pass


    '''

    Conference Bridge

    '''

    def add_cfb(self, cfb_data):

        try:
            result = self.service.addConferenceBridge(conferenceBridge=cfb_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_cfb_cms(self, name, description, cfb_prefix, sip_trunk,
                    security_icon_control, override_dest, addresses,
                    username, password, port):
        cms_data = {
            'name': name,
            'description': description,
            'product': 'Cisco Meeting Server',
            'conferenceBridgePrefix': cfb_prefix,
            'sipTrunkName': sip_trunk,
            'allowCFBControlOfCallSecurityIcon': security_icon_control,
            'overrideSIPTrunkAddress': override_dest,
            'addresses': {
                'address': addresses
            },
            'userName': username,
            'password': password,
            'httpPort': port
        }

        result = self.add_cfb(cms_data)

        return result

    def get_cfb(self, name):

        try:
            result = self.service.getConferenceBridge(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_cfb(self, name):
        pass

        # try:
        #     result = self.service.removeCss(name=name)
        # except Exception as fault:
        #     result = None
        #     self.last_exception = fault
        #
        # return result

    def update_cfb(self, css_name, description, partition_list):
        pass

        # members = {'member': []}
        #
        # css_index = 1
        #
        # for partition in partition_list:
        #     partition_data = {'routePartitionName': partition,
        #                       'index': css_index}
        #     members['member'].append(partition_data)
        #     css_index += 1
        #
        # try:
        #     result = self.service.updateCss(name=css_name, description=description, members=members)
        # except Exception as fault:
        #     result = None
        #     self.last_exception = fault
        #
        # return result

    '''

    Media Resource Group

    '''

    def get_mrg(self, name):

        try:
            result = self.service.getMediaResourceGroup(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''

    Media Resource Group List

    '''

    def get_mrgl(self, name):

        try:
            result = self.service.getMediaResourceList(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''

    Device Pool

    '''

    def get_device_pool(self, name):

        try:
            result = self.service.getDevicePool(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''
    
    Device Security Profile
    
    '''

    def get_phone_security_profile(self, name):

        try:
            result = self.service.getPhoneSecurityProfile(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_phone_security_profile(self, phone_type, protocol, name, description, device_security_mode,
                                   authentication_mode, key_size, key_order, ec_key_size, tftp_encrypted_config,
                                   nonce_validity_time, transport_type, sip_phone_port, enable_digest_auth):

        security_profile = {'phoneType': phone_type,
                            'protocol': protocol,
                            'name': name,
                            'description': description,
                            'deviceSecurityMode': device_security_mode,
                            'authenticationMode': authentication_mode,
                            'keySize': key_size,
                            'keyOrder': key_order,
                            'ecKeySize': ec_key_size,
                            'tftpEncryptedConfig': tftp_encrypted_config,
                            'nonceValidityTime': nonce_validity_time,
                            'transportType': transport_type,
                            'sipPhonePort': sip_phone_port,
                            'enableDigestAuthentication': enable_digest_auth,
                            }

        try:
            result = self.service.addPhoneSecurityProfile(phoneSecurityProfile=security_profile)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''

    SIP Trunk Security Profile

    '''

    def get_sip_trunk_security_profile(self, name):

        try:
            result = self.service.getSipTrunkSecurityProfile(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_sip_trunk_security_profile(self, name, description, security_mode, incoming_transport, outgoing_transport,
                                       digest_auth, nonce_policy_time, x509_subject_name, incoming_port,
                                       app_level_auth, accept_presence_subscription, accept_ood_refer,
                                       accept_unsolicited_notify, allow_replaces, transmit_security_status,
                                       sip_v150_outbound_offer_filter, allow_charging_header):

        security_profile = {
            'name': name,
            'description': description,
            'securityMode': security_mode,
            'incomingTransport': incoming_transport,
            'outgoingTransport': outgoing_transport,
            'digestAuthentication': digest_auth,
            'noncePolicyTime': nonce_policy_time,
            'x509SubjectName': x509_subject_name,
            'incomingPort': incoming_port,
            'applLevelAuthentication': app_level_auth,
            'acceptPresenceSubscription': accept_presence_subscription,
            'acceptOutOfDialogRefer': accept_ood_refer,
            'acceptUnsolicitedNotification': accept_unsolicited_notify,
            'allowReplaceHeader': allow_replaces,
            'transmitSecurityStatus': transmit_security_status,
            'sipV150OutboundSdpOfferFiltering': sip_v150_outbound_offer_filter,
            'allowChargingHeader': allow_charging_header,
        }

        try:
            result = self.service.addSipTrunkSecurityProfile(sipTrunkSecurityProfile=security_profile)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_sip_trunk_security_profile(self, name):

        try:
            result = self.service.removeSipTrunkSecurityProfile(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result



    ''' 
    
    SIP Profile
    
    '''


    def get_sip_profile(self, name):

        try:
            result = self.service.getSipProfile(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_sip_profile(self, profile_data):

        try:
            result = self.service.addSipProfile(sipProfile=profile_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_sip_profile(self, profile_data):

        try:
            result = self.service.updateSipProfile(**profile_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    ''' 

    SIP Trunk

    '''

    def get_sip_trunk(self, name):

        try:
            result = self.service.getSipTrunk(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def remove_sip_trunk(self, name):

        try:
            result = self.service.removeSipTrunk(name=name)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def add_sip_trunk(self, trunk_data):

        try:
            result = self.service.addSipTrunk(sipTrunk=trunk_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def update_sip_trunk(self, trunk_data):

        try:
            result = self.service.updateSipTrunk(**trunk_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    '''
    
    Reset / Restart Devices
    
    '''

    def do_reset_restart_device(self, device, is_hard_reset, is_mgcp):
        reset_data = {
            'deviceName': device,
            'isHardReset': is_hard_reset,
            'isMGCP': is_mgcp
        }

        try:
            result = self.service.doDeviceReset(**reset_data)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result

    def reset_device(self, device):
        result = self.do_reset_restart_device(device, True, False)

        return result

    def restart_device(self, device):
        result = self.do_reset_restart_device(device, False, False)

        return result

    def reset_mgcp(self, device):
        result = self.do_reset_restart_device(device, True, True)

        return result

    def restart_mgcp(self, device):
        result = self.do_reset_restart_device(device, False, True)

        return result


    '''
    
    Service Parameters
    
    '''

    def sql_update_service_parameter(self, name, value):

        query = "update processconfig set paramvalue = '{0}' where paramname = '{1}'".format(value, name)

        sql_result = self.run_sql_update(query)

        if sql_result['rows_updated'] > 0:
            result = True
        else:
            result = False

        return result

    def sql_get_service_parameter(self, name):

        query = "select * from processconfig where paramname = '{0}'".format(name)

        sql_result = self.run_sql_query(query)

        if sql_result['num_rows'] > 0:
            result = sql_result['rows']
        else:
            result = None

        return result


    '''
    
    Device Association
    
    '''

    def sql_associate_device_to_user(self, device, userid, association_type='1'):

        device_pkid = self.sql_get_device_pkid(device)
        enduser_pkid = self.sql_get_enduser_pkid(userid)

        if device_pkid is not None and enduser_pkid is not None:

            query = "insert into enduserdevicemap (fkenduser, fkdevice, defaultprofile, tkuserassociation) " \
                    "values ('{0}','{1}','f','{2}')".format(enduser_pkid, device_pkid, association_type)

            sql_result = self.run_sql_update(query)

            if sql_result['rows_updated'] > 0:
                result = True
            else:
                result = False

            return result


    '''
    
    Remote Destinations
    
    '''

    def get_remote_destination(self, destination):
        try:
            result = self.service.getRemoteDestination(destination=destination)
        except Exception as fault:
            result = None
            self.last_exception = fault

        return result


    def check_connectivity(self):
        pass


class UcmServiceabilityToolkit:
    last_exception = None

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/controlcenterservice2/services/ControlCenterServices?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_serviceability.db', timeout=60)

        self.client = Client(wsdl=wsdl, transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.service

        # enable_logging()

    def get_service(self):
        return self.service


class UcmRisPortToolkit:
    last_exception = None

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/realtimeservice2/services/RISService70?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_risport.db', timeout=60)

        self.client = Client(wsdl=wsdl, transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.create_service("{http://schemas.cisco.com/ast/soap}RisBinding",
                                                  "https://{0}:8443/realtimeservice2/services/RISService70".format(server_ip))

        enable_logging()

    def get_service(self):
        return self.service


class UcmPerfMonToolkit:
    last_exception = None
    compiled_re = None
    history = HistoryPlugin()

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/perfmonservice2/services/PerfmonService?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_risport.db', timeout=60)

        self.client = Client(wsdl=wsdl, plugins=[self.history], transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.create_service("{http://schemas.cisco.com/ast/soap}PerfmonBinding",
                                                  "https://{0}:8443/perfmonservice2/services/PerfmonService".format(server_ip))

        # enable_logging()

    def get_service(self):
        return self.service

    def last_request_debug(self):
        request_env = tostring(self.history.last_sent['envelope'])
        request_headers = self.history.last_sent['http_headers']
        response_env = tostring(self.history.last_received['envelope'])
        response_headers = self.history.last_received['http_headers']

        return {
            'request': {
                'raw': self.history.last_sent,
                'headers': request_headers,
                'envelope': request_env
            },
            'response': {
                'raw': self.history.last_received,
                'headers': response_headers,
                'envelope': response_env

            }
         }

    def decode_counter_name(self, counter_name_string):
        # Converts string like \\\\vnt-cm1b.cisco.com\\Cisco Locations LBM(BranchRemote->Hub_None)\\BandwidthAvailable
        #  to an object

        decoded_counter = None

        if self.compiled_re is None:
            self.compiled_re = re.compile(r"""\\\\([^\\]*)\\([^()\\]*)(\(([^\\]*)\))?\\([^\\]*)""")

        match_result = self.compiled_re.match(counter_name_string)

        if match_result is not None:
            decoded_counter = {
                'host': match_result.group(1),
                'object': match_result.group(2),
                'instance': match_result.group(4),
                'counter': match_result.group(5)
            }

        return decoded_counter


    def perfmonOpenSession(self):
        session_handle = self.service.perfmonOpenSession()
        return session_handle

    def perfmonAddCounter(self, session_handle, counters):
        '''
        :param session_handle: A session Handle returned from perfmonOpenSession()
        :param counters: An array of counters or a single string for a single counter
        :return: True for Success and False for Failure
        '''

        counter_data = []

        if isinstance(counters, list):
            counter_data = [
                {
                    'Counter': []
                }
            ]

            for counter in counters:
                new_counter = {
                    'Name': counter
                }
                counter_data[0]['Counter'].append(new_counter)

        elif counters is not None:
            counter_data = [
                {
                    'Counter': [
                        {
                            'Name': counters
                        }
                    ]
                }
            ]

        try:
            self.service.perfmonAddCounter(SessionHandle=session_handle, ArrayOfCounter=counter_data)
            result = True
        except Exception as e:
            result = False

        return result

    def perfmonRemoveCounter(self, session_handle, counters):
        '''
        :param session_handle: A session Handle returned from perfmonOpenSession()
        :param counters: An array of counters or a single string for a single counter
        :return: True for Success and False for Failure
        '''

        counter_data = []

        if isinstance(counters, list):
            counter_data = [
                {
                    'Counter': []
                }
            ]

            for counter in counters:
                new_counter = {
                    'Name': counter
                }
                counter_data[0]['Counter'].append(new_counter)

        elif counters is not None:
            counter_data = [
                {
                    'Counter': [
                        {
                            'Name': counters
                        }
                    ]
                }
            ]

        try:
            self.service.perfmonRemoveCounter(SessionHandle=session_handle, ArrayOfCounter=counter_data)
            result = True
        except Exception as e:
            result = False

        return result


    def perfmonCollectSessionData(self, session_handle):
        try:
            session_data = self.service.perfmonCollectSessionData(SessionHandle=session_handle)

            result_data = {}

            for data in session_data:
                counter_name_data = self.decode_counter_name(data['Name']['_value_1'])
                if counter_name_data is not None:
                    counter_host = counter_name_data['host']
                    counter_object = counter_name_data['object']
                    counter_instance = counter_name_data['instance']
                    counter_name = counter_name_data['counter']
                    counter_value = data['Value']
                    counter_status = data['CStatus']
                    if counter_status == 0:
                        if counter_host not in result_data:
                            result_data[counter_host] = {}
                        if counter_object not in result_data[counter_host]:
                            result_data[counter_host][counter_object] = {}

                        if counter_instance is None:
                            result_data[counter_host][counter_object]['multi_instance'] = False
                            if 'counters' not in result_data[counter_host][counter_object]:
                                result_data[counter_host][counter_object]['counters'] = {}
                            result_data[counter_host][counter_object]['counters'][counter_name] = counter_value
                        else:
                            result_data[counter_host][counter_object]['multi_instance'] = True
                            if 'instances' not in result_data[counter_host][counter_object]:
                                result_data[counter_host][counter_object]['instances'] = {}
                            if counter_instance not in result_data[counter_host][counter_object]['instances']:
                                result_data[counter_host][counter_object]['instances'][counter_instance] = {}
                            result_data[counter_host][counter_object]['instances'][counter_instance][counter_name] = counter_value
                    else:
                        # TODO: Clean up the session and restart it if we're not getting valid data
                        pass
        except Exception as e:
            print(e)
            result_data = None

        return result_data

    def perfmonCloseSession(self, session_handle):
        try:
            session_handle = self.service.perfmonCloseSession(SessionHandle=session_handle)
        except Exception as e:
            session_handle = None
        return session_handle

    def perfmonListCounter(self, host):
        try:
            counter_list = {}
            counter_data = self.service.perfmonListCounter(Host=host)
            for object_data in counter_data:
                object_name = object_data['Name']['_value_1']
                counter_list[object_name] = {}
                counter_list[object_name]['multi_instance'] = object_data['MultiInstance']
                counter_list[object_name]['counters'] = []
                for counter in object_data['ArrayOfCounter']['item']:
                    counter_list[object_name]['counters'].append(counter['Name']['_value_1'])
        except Exception as e:
            counter_list = None

        return counter_list

    def perfmonListInstance(self, host, object_name):
        try:
            instance_data = self.service.perfmonListInstance(Host=host, Object=object_name)

            instances = []

            for instance in instance_data:
                instances.append(instance['Name']['_value_1'])
        except Exception as e:
            instances = None

        return instances



class UcmLogCollectionToolkit:

    last_exception = None

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/logcollectionservice2/services/LogCollectionPortTypeService?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_logcollection.db', timeout=60)

        self.client = Client(wsdl=wsdl, transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.service

        enable_logging()

    def get_service(self):
        return self.service


class UcmDimeGetFileToolkit:

    last_exception = None

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, tls_verify=True):
        wsdl = 'https://{0}:8443/logcollectionservice/services/DimeGetFileService?wsdl'.format(server_ip)

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_logcollection.db', timeout=60)

        self.client = Client(wsdl=wsdl, transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.service

        enable_logging()

    def get_service(self):
        return self.service


class PawsToolkit:

    last_exception = None

    '''

    Constructor - Create new instance 

    '''

    def __init__(self, username, password, server_ip, service, tls_verify=True):

        dir = os.path.dirname(__file__)

        if (service == 'HardwareInformationService'):
            wsdl = os.path.join(dir, 'paws/hardware_information_service.wsdl')
            binding = "{http://services.api.platform.vos.cisco.com}HardwareInformationServiceSoap11Binding"
            endpoint = "https://{0}:8443/platform-services/services/HardwareInformationService.HardwareInformationServiceHttpsSoap11Endpoint/".format(server_ip)
        elif service == 'VersionService':
            wsdl = 'https://{0}:8443/platform-services/services/VersionService?wsdl'.format(server_ip)
            binding = "{http://services.api.platform.vos.cisco.com}VersionServiceSoap12Binding"
            endpoint = "https://{0}:8443/platform-services/services/VersionService.VersionServiceHttpsSoap12Endpoint/".format(server_ip)  # nopep8
        elif service == 'OptionsService':
            wsdl = 'https://{0}:8443/platform-services/services/OptionsService?wsdl'.format(server_ip)
            binding = "{http://services.api.platform.vos.cisco.com}OptionsServiceSoap12Binding"
            endpoint = "https://{0}:8443/platform-services/services/OptionsService.OptionsServiceHttpsSoap12Endpoint/".format(server_ip)  # nopep8
        elif service == 'ProductService':
            wsdl = 'https://{0}:8443/platform-services/services/ProductService?wsdl'.format(server_ip)
            binding = "{http://services.api.platform.vos.cisco.com}ProductServiceSoap12Binding"
            endpoint = "https://{0}:8443/platform-services/services/ProductService.ProductServiceHttpsSoap12Endpoint/".format(server_ip)  # nopep8
        elif service == 'VersionService':
            wsdl = 'https://{0}:8443/platform-services/services/VersionService?wsdl'.format(server_ip)
            binding = "{http://services.api.platform.vos.cisco.com}VersionServiceSoap12Binding"
            endpoint = "https://{0}:8443/platform-services/services/VersionService.VersionServiceHttpsSoap12Endpoint/".format(server_ip)  # nopep8
        elif service == 'ClusterNodesService':
            wsdl = 'https://{0}:8443/platform-services/services/ClusterNodesService?wsdl'.format(server_ip)
            binding = "{http://services.api.platform.vos.cisco.com}ClusterNodesServiceSoap12Binding"
            endpoint = "https://{0}:8443/platform-services/services/ClusterNodesService.ClusterNodesServiceHttpsSoap12Endpoint/".format(server_ip)  # nopep8

        self.session = Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = tls_verify

        self.cache = SqliteCache(path=tempfile.gettempdir()+'/sqlite_paws.db', timeout=60)

        self.client = Client(wsdl=wsdl, transport=Transport(cache=self.cache, session=self.session))

        self.service = self.client.create_service(binding, endpoint)

        # enable_logging()

    def get_service(self):
        return self.service

    def get_hardware_information(self):
        hw_info = self.service.getHardwareInformation()

        return hw_info

    def get_active_version(self):
        active_version = self.service.getActiveVersion()

        return active_version


