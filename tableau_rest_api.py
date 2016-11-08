# -*- coding: utf-8 -*-

# Python 2.x only
import urllib2

# For parsing XML responses
from lxml import etree

# StringIO helps with lxml UTF8 parsing

from StringIO import StringIO
import math
import time
import random
import os
import re
import copy
import zipfile
import shutil
import sys
from HTMLParser import HTMLParser

# Implements logging features across all objects
class TableauBase:
    def __init__(self):
        self.logger = None

    def enable_logging(self, logger_obj):
        if isinstance(logger_obj, Logger):
            self.logger = logger_obj

    def log(self, l):
        if self.logger is not None:
            self.logger.log(l)

    def start_log_block(self):
        if self.logger is not None:
            self.logger.start_log_block()

    def end_log_block(self):
        if self.logger is not None:
            self.logger.end_log_block()

    def log_uri(self, uri, verb):
        if self.logger is not None:
            self.logger.log_uri(verb, uri)

    def log_xml_request(self, xml, verb):
        if self.logger is not None:
            self.logger.log_xml_request(verb, xml)

class Logger:
    def __init__(self, filename):
        try:
            lh = open(filename, 'wb')
            self.__log_handle = lh
        except IOError:
            print u"Error: File '{}' cannot be opened to write for logging".format(filename)
            raise

    def log(self, l):
        cur_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log_line = cur_time + " : " + l + "\n"
        try:
            self.__log_handle.write(log_line.encode('utf8'))
        except UnicodeDecodeError as e:
            self.__log_handle.write(log_line)

    def start_log_block(self):
        caller_function_name = sys._getframe(2).f_code.co_name
        cur_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()).encode('utf-8')
        log_line = u'---------- {} started at {} ----------\n'.format(caller_function_name, cur_time)
        self.__log_handle.write(log_line.encode('utf-8'))

    def end_log_block(self):
        caller_function_name = sys._getframe(2).f_code.co_name
        cur_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()).encode('utf-8')
        log_line = u'---------- {} ended at {} ------------\n'.format(caller_function_name, cur_time)
        self.__log_handle.write(log_line.encode('utf-8'))

    def log_uri(self, uri, verb):
        self.log(u'Sending {} request via: {}'.format(verb, uri))

    def log_xml_request(self, xml, verb):
        self.log(u'Sending {} request with XML: {}'.format(verb, xml))

class TableauRestApi(TableauBase):
    # Defines a class that represents a RESTful connection to Tableau Server. Use full URL (http:// or https://)
    def __init__(self, server, username, password, site_content_url=""):
        if server.find('http') == -1:
            raise InvalidOptionException('Server URL must include http:// or https://')
        self.__server = server
        self._site_content_url = site_content_url
        self.__username = username
        self.__password = password
        self.__token = None  # Holds the login token from the Sign In call
        self.__site_luid = ""
        self.__user_luid = ""
        self.__login_as_user_id = None
        self.__last_error = None
        self.logger = None
        self.__last_response_content_type = None
        self.__luid_pattern = r"[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*"
        self.__tableau_namespace = u'http://tableausoftware.com/api'
        self.__project_caps = (u'ProjectLeader', )
        self.__datasource_caps = (
            u'ChangePermissions',
            u'Connect',
            u'Delete',
            u'ExportXml',
            u'Read',
            u'Write'
        )
        self.__workbook_caps = (
            u'AddComment',
            u'ChangeHierarchy',
            u'ChangePermissions',
            u'Delete',
            u'ExportData',
            u'ExportImage',
            u'ExportXml',
            u'Filter',
            u'Read',
            u'ShareView',
            u'ViewComments',
            u'ViewUnderlyingData',
            u'WebAuthoring',
            u'Write'
        )
        self.__site_roles = (
            u'Interactor',
            u'Publisher',
            u'SiteAdministrator',
            u'Unlicensed',
            u'UnlicensedWithPublish',
            u'Viewer',
            u'ViewerWithPublish',
            u'ServerAdministrator'
        )
        self.__permissionable_objects = [u'datasource', u'project', u'workbook']
        self.__ns_map = {'t': 'http://tableausoftware.com/api'}
        self.__server_to_rest_capability_map = {
            u'Add Comment': u'AddComment',
            u'Move': u'ChangeHierarchy',
            u'Set Permissions': u'ChangePermissions',
            u'Connect': u'Connect',
            u'Delete': u'Delete',
            u'View Summary Data': u'ExportData',
            u'Export Image': u'ExportImage',
            u'Download': u'ExportXml',
            u'Filter': u'Filter',
            u'Project Leader': u'ProjectLeader',
            u'View': u'Read',
            u'Share Customized': u'ShareView',
            u'View Comments': u'ViewComments',
            u'View Underlying Data': u'ViewUnderlyingData',
            u'Web Edit': u'WebAuthoring',
            u'Save': u'Write'
        }

    #
    # Object helpers and setter/getters
    #

    def get_last_error(self):
        self.log(self.__last_error)
        return self.__last_error

    def set_last_error(self, error):
        self.__last_error = error

    # Method to handle single str or list and return a list
    @staticmethod
    def to_list(x):
        if isinstance(x, (str, unicode)):
            l = [x]  # Make single into a collection
        else:
            l = x
        return l

    # Method to read file in x MB chunks for upload, 10 MB by default (1024 bytes = KB, * 1024 = MB, * 10)
    @staticmethod
    def __read_file_in_chunks(file_object, chunk_size=(1024 * 1024 * 10)):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    # You must generate a boundary string that is used both in the headers and the generated request that you post.
    # This builds a simple 30 hex digit string
    @staticmethod
    def generate_boundary_string():
        random_digits = [random.SystemRandom().choice('0123456789abcdef') for n in xrange(30)]
        s = "".join(random_digits)
        return s

    # Convert a permission
    def convert_server_permission_name_to_rest_permission(self, permission_name):
        if permission_name in self.__server_to_rest_capability_map:
            return self.__server_to_rest_capability_map[permission_name]
        else:
            raise InvalidOptionException(u'{} is not a permission name on the Tableau Server'.format(permission_name))

    # 32 hex characters with 4 dashes
    def is_luid(self, val):
        if len(val) == 36:
            if re.match(self.__luid_pattern, val) is not None:
                return True
            else:
                return False
        else:
            return False

    def get_lxml_ns_prefix(self):
        return '{' + self.__ns_map['t'] + '}'

    #
    # REST API Helper Methods
    #

    def build_api_url(self, call, login=False):
        if login is True:
            return self.__server + u"/api/2.0/" + call
        else:
            return self.__server + u"/api/2.0/sites/" + self.__site_luid + u"/" + call

    # URI is different form actual URL you need to load a particular view in iframe
    @staticmethod
    def convert_view_content_url_to_embed_url(content_url):
        split_url = content_url.split('/')
        return 'views/' + split_url[0] + "/" + split_url[2]

    # Generic method for XML lists for the "query" actions to name -> id dict
    @staticmethod
    def convert_xml_list_to_name_id_dict(lxml_obj):
        d = {}
        for element in lxml_obj:
            e_id = element.get("id")
            # If list is collection, have to run one deeper
            if e_id is None:
                for list_element in element:
                    e_id = list_element.get("id")
                    name = list_element.get("name")
                    d[name] = e_id
            else:
                name = element.get("name")
                d[name] = e_id
        return d

    #
    # Internal REST API Helpers (mostly XML definitions that are reused between methods)
    #
    @staticmethod
    def __build_site_request_xml(site_name=None, content_url=None, admin_mode=None, user_quota=None,
                                 storage_quota=None, disable_subscriptions=None, state=None):
        request = u'<tsRequest><site '
        if site_name is not None:
            request += u'name="{}" '.format(site_name)
        if content_url is not None:
            request += u'contentUrl="{}" '.format(content_url)
        if admin_mode is not None:
            request += u'adminMode="{}" '.format(admin_mode)
        if user_quota is not None:
            request += u'userQuota="{}" '.format(user_quota)
        if state is not None:
            request += u'state="{}" '.format(state)
        if storage_quota is not None:
            request += u'storageQuota="{}" '.format(storage_quota)
        if disable_subscriptions is not None:
            request += u'disableSubscriptions="{}" '.format(disable_subscriptions)
        request += u'/></tsRequest>'
        return request

    @staticmethod
    def __build_connection_update_xml(new_server_address=None, new_server_port=None,
                                      new_connection_username=None, new_connection_password=None):
        update_request = u"<tsRequest><connection "
        if new_server_address is not None:
            update_request += u'serverAddress="{}" '.format(new_server_address)
        if new_server_port is not None:
            update_request += u'serverPort="{}" '.format(new_server_port)
        if new_connection_username is not None:
            update_request += u'userName="{}" '.format(new_connection_username)
        if new_connection_username is not None:
            update_request += u'password="{}"'.format(new_connection_password)
        update_request += u"/></tsRequest>"
        return update_request

    # Dict { capability_name : mode } into XML with checks for validity. Set type to 'workbook' or 'datasource'
    def build_capabilities_xml_from_dict(self, capabilities_dict, obj_type):
        if obj_type not in self.__permissionable_objects:
            error_text = u'objtype can only be "project", "workbook" or "datasource", was given {}'
            raise InvalidOptionException(error_text.format(u'obj_type'))
        xml = u'<capabilities>\n'
        for cap in capabilities_dict:
            # Skip if the capability is set to None
            if capabilities_dict[cap] is None:
                continue
            if capabilities_dict[cap] not in [u'Allow', u'Deny']:
                raise InvalidOptionException(u'Capability mode can only be "Allow",  "Deny" (case-sensitive)')
            if obj_type == u'project':
                if cap not in self.__datasource_caps + self.__workbook_caps + self.__project_caps:
                    raise InvalidOptionException(u'{} is not a valid capability in the REST API'.format(cap))
            if obj_type == u'datasource':
                # Ignore if not available for datasource
                if cap not in self.__datasource_caps:
                    self.log(u'{} is not a valid capability for a datasource'.format(cap))
                    continue
            if obj_type == u'workbook':
                # Ignore if not available for workbook
                if cap not in self.__workbook_caps:
                    self.log(u'{} is not a valid capability for a workbook'.format(cap))
                    continue
            xml += u'<capability name="{}" mode="{}" />'.format(cap, capabilities_dict[cap])
        xml += u'</capabilities>'
        return xml

    # Turns lxml that is returned when asking for permissions into a bunch of GranteeCapabilities objects
    def convert_capabilities_xml_into_obj_list(self, lxml_obj):
        self.start_log_block()
        obj_list = []
        xml = lxml_obj.xpath(u'//t:granteeCapabilities', namespaces=self.__ns_map)
        if len(xml) == 0:
            raise NoMatchFoundException(u"No granteeCapabilities tags found")
        else:
            for gcaps in xml:
                for tags in gcaps:
                    # Namespace fun
                    if tags.tag == u'{}group'.format(self.get_lxml_ns_prefix()):
                        luid = tags.get('id')
                        gcap_obj = GranteeCapabilities(u'group', luid)
                        self.log(u'group {}'.format(luid))
                    elif tags.tag == u'{}user'.format(self.get_lxml_ns_prefix()):
                        luid = tags.get('id')
                        gcap_obj = GranteeCapabilities(u'user', luid)
                        self.log(u'user {}'.format(luid))
                    elif tags.tag == u'{}capabilities'.format(self.get_lxml_ns_prefix()):
                        for caps in tags:
                            self.log(caps.get('name') + ' : ' + caps.get('mode'))
                            gcap_obj.set_capability(caps.get('name'), caps.get('mode'))
                obj_list.append(gcap_obj)
            self.log(u'Gcap object list has {} items'.format(unicode(len(obj_list))))
            self.end_log_block()
            return obj_list

    # Runs through the gcap object list, and tries to do a conversion all principals to matching LUIDs on current site
    # Use case is replicating settings from one site to another
    # Orig_site must be TableauRestApi
    def convert_gcap_obj_list_from_orig_site_to_current_site(self, gcap_obj_list, orig_site):
        new_gcap_obj_list = []
        orig_site_groups = orig_site.query_groups()
        orig_site_users = orig_site.query_users()
        orig_site_groups_dict = self.convert_xml_list_to_name_id_dict(orig_site_groups)
        orig_site_users_dict = self.convert_xml_list_to_name_id_dict(orig_site_users)

        new_site_groups = self.query_groups()
        new_site_users = self.query_users()
        new_site_groups_dict = self.convert_xml_list_to_name_id_dict(new_site_groups)
        new_site_users_dict = self.convert_xml_list_to_name_id_dict(new_site_users)
        for gcap_obj in gcap_obj_list:
            orig_luid = gcap_obj.get_luid()
            if gcap_obj.get_obj_type() == 'group':
                # Find the name that matches the LUID
                try:
                    orig_name = (key for key, value in orig_site_groups_dict.items() if value == orig_luid).next()
                except StopIteration:
                    raise NoMatchFoundException(u"No matching name for luid {} found on the original site".format(
                                                orig_luid))
                new_luid = new_site_groups_dict.get(orig_name)

            elif gcap_obj.get_obj_type() == 'user':
                # Find the name that matches the LUID
                try:
                    orig_name = (key for key, value in orig_site_users_dict.items() if value == orig_luid).next()
                except StopIteration:
                    raise NoMatchFoundException(u"No matching name for luid {} found on the original site".format(
                                                orig_luid))
                new_luid = new_site_users_dict.get(orig_name)

            new_gcap_obj = copy.copy(gcap_obj)
            if new_luid is None:
                raise NoMatchFoundException(u"No matching {} named {} found on the new site".format(
                                            gcap_obj.get_obj_type(), orig_name))
            new_gcap_obj.set_luid(new_luid)
            new_gcap_obj_list.append(new_gcap_obj)
        return new_gcap_obj_list

    # Determine if capabilities are already set identically (or identically enough) to skip
    @staticmethod
    def are_capabilities_obj_lists_identical(new_obj_list, dest_obj_list):
        # Grab the LUIDs of each, determine if they match in the first place

        # Create a dict with the LUID as the keys for sorting and comparison
        new_obj_dict = {}
        for obj in new_obj_list:
            new_obj_dict[obj.get_luid()] = obj

        dest_obj_dict = {}
        for obj in dest_obj_list:
            dest_obj_dict[obj.get_luid()] = obj

        # If lengths don't match, they must differ
        if len(new_obj_dict) != len(dest_obj_dict):
            return False
        else:
            # If LUIDs don't match, they must differ
            new_obj_luids = new_obj_dict.keys()
            dest_obj_luids = dest_obj_dict.keys()
            new_obj_luids.sort()
            dest_obj_luids.sort()
            if cmp(new_obj_luids, dest_obj_luids) != 0:
                return False
            # Run through each to compare
            else:
                # At this point, we know they must match up
                for luid in new_obj_luids:
                    new_obj = new_obj_dict.get(luid)
                    dest_obj = dest_obj_dict.get(luid)
                    new_obj_cap_dict = new_obj.get_capabilities_dict()
                    dest_obj_cap_dict = dest_obj.get_capabilities_dict()
                    if cmp(new_obj_cap_dict, dest_obj_cap_dict):
                        return True
                    else:
                        return False

    # Looks at LUIDs in new_obj_list, if they exist in the dest_obj, compares their gcap objects, if match returns True
    @staticmethod
    def are_capabilities_objs_identical_for_matching_luids(new_obj_list, dest_obj_list):
        # Create a dict with the LUID as the keys for sorting and comparison
        new_obj_dict = {}
        for obj in new_obj_list:
            new_obj_dict[obj.get_luid()] = obj

        dest_obj_dict = {}
        for obj in dest_obj_list:
            dest_obj_dict[obj.get_luid()] = obj

        new_obj_luids = new_obj_dict.keys()
        dest_obj_luids = dest_obj_dict.keys()

        if set(dest_obj_luids).issuperset(new_obj_luids):
            # At this point, we know the new_objs do exist on the current obj, so let's see if they are identical
            for luid in new_obj_luids:
                new_obj = new_obj_dict.get(luid)
                dest_obj = dest_obj_dict.get(luid)
                new_obj_cap_dict = new_obj.get_capabilities_dict()
                dest_obj_cap_dict = dest_obj.get_capabilities_dict()
                if cmp(new_obj_cap_dict, dest_obj_cap_dict):
                    return True
                else:
                    return False
        else:
            return False
#
    # Sign-in and Sign-out
    #

    def signin(self):
        self.start_log_block()
        if self._site_content_url.lower() in ['default', '']:
            login_payload = u'<tsRequest><credentials name="{}" password="{}" >'.format(self.__username, self.__password)
            login_payload += u'<site /></credentials></tsRequest>'
        else:
            login_payload = u'<tsRequest><credentials name="{}" password="{}" >'.format(self.__username, self.__password)
            login_payload += u'<site contentUrl="{}" /></credentials></tsRequest>'.format(self._site_content_url)
        url = self.build_api_url(u"auth/signin", login=True)

        self.log(u'Logging in via: {}'.format(url.encode('utf-8')))
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_xml_request(login_payload)
        api.set_http_verb('post')
        self.log(u'Login payload is\n {}'.format(login_payload))
        api.request_from_api(0)
        # self.log(api.get_raw_response())
        xml = api.get_response()
        credentials_element = xml.xpath(u'//t:credentials', namespaces=self.__ns_map)
        self.__token = credentials_element[0].get("token").encode('utf-8')
        self.log(u"Token is " + self.__token)
        self.__site_luid = credentials_element[0].xpath(u"//t:site", namespaces=self.__ns_map)[0].get("id").encode('utf-8')
        self.__user_luid = credentials_element[0].xpath(u"//t:user", namespaces=self.__ns_map)[0].get("id").encode('utf-8')
        self.log(u"Site ID is " + self.__site_luid)
        self.end_log_block()

    def signout(self):
        self.start_log_block()
        url = self.build_api_url(u"auth/signout", login=True)
        self.log(u'Logging out via: {}'.format(url.encode('utf-8')))
        api = RestXmlRequest(url, False, self.logger)
        api.set_http_verb('post')
        api.request_from_api()
        self.log(u'Signed out successfully')
        self.end_log_block()

    #
    # HTTP "verb" methods. These actually communicate with the RestXmlRequest object to place the requests
    #

    # baseline method for any get request. appends to base url
    def query_resource(self, url_ending, login=False):
        self.start_log_block()
        api_call = self.build_api_url(url_ending, login)
        api = RestXmlRequest(api_call, self.__token, self.logger)
        self.log_uri(u'get', api_call)
        api.request_from_api()
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        self.end_log_block()
        return xml

    def send_post_request(self, url):
        self.start_log_block()
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_http_verb(u'post')
        api.request_from_api(0)
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        self.end_log_block()
        return xml

    def send_add_request(self, url, request):
        self.start_log_block()
        self.log_uri(u'add', url)
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_xml_request(request)
        self.log_xml_request(u'add', request)
        api.set_http_verb('post')
        api.request_from_api(0)  # Zero disables paging, for all non queries
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        self.end_log_block()
        return xml

    def send_update_request(self, url, request):
        self.start_log_block()
        self.log_uri(u'update', url)
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_xml_request(request)
        api.set_http_verb(u'put')
        self.log_xml_request(u'update', request)
        api.request_from_api(0)  # Zero disables paging, for all non queries
        self.end_log_block()
        return api.get_response()

    def send_delete_request(self, url):
        self.start_log_block()
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_http_verb(u'delete')
        self.log_uri(u'delete', url)
        try:
            api.request_from_api(0)  # Zero disables paging, for all non queries
            self.end_log_block()
            # Return for counter
            return 1
        except RecoverableHTTPException as e:
            self.log(u'Non fatal HTTP Exception Response {}, Tableau Code {}'.format(e.http_code, e.tableau_error_code))
            if e.tableau_error_code in [404003, 404002]:
                self.log(u'Delete action did not find the resouce. Consider successful, keep going')
            self.end_log_block()
        except:
            raise

    def send_publish_request(self, url, request, boundary_string):
        self.start_log_block()
        self.log_uri(u'publish', url)
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_publish_content(request, boundary_string)
        api.set_http_verb(u'post')
        api.request_from_api(0)
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        self.end_log_block()
        return xml

    def send_append_request(self, url, request, boundary_string):
        self.start_log_block()
        self.log_uri(u'append', url)
        api = RestXmlRequest(url, self.__token, self.logger)
        api.set_publish_content(request, boundary_string)
        api.set_http_verb(u'put')
        api.request_from_api(0)
        xml = api.get_response().getroot()  # return Element rather than ElementTree
        self.end_log_block()
        return xml

    # Used when the result is not going to be XML and you want to save the raw response as binary
    def send_binary_get_request(self, url):
        self.start_log_block()
        api = RestXmlRequest(url, self.__token, self.logger)
        self.log_uri(u'binary get', url)
        api.set_http_verb(u'get')
        api.set_response_type(u'binary')
        api.request_from_api(0)
        # Set this content type so we can set the file externsion
        self.__last_response_content_type = api.get_last_response_content_type()
        self.end_log_block()
        return api.get_response()

#
# Basic Querying / Get Methods
#

    #
    # Begin Datasource Querying Methods
    #

    def query_datasources(self):
        self.start_log_block()
        datasources = self.query_resource(u"datasources")
        self.end_log_block()
        return datasources

    def query_datasource_by_luid(self, luid):
        self.start_log_block()
        luid = self.query_resource(u'datasources/{}'.format(luid))
        self.end_log_block()
        return luid

    # Datasources in different projects can have the same 'pretty name'.
    def query_datasource_luid_by_name_in_project(self, name, p_name_or_luid=False):
        self.start_log_block()
        datasources = self.query_datasources()
        datasources_with_name = datasources.xpath(u'//t:datasource[@name="{}"]'.format(name), namespaces=self.__ns_map)
        if len(datasources_with_name) == 0:
            self.end_log_block()
            raise NoMatchFoundException(u"No datasource found with name {} in any project".format(name))
        elif len(datasources_with_name) == 1:
            self.end_log_block()
            return datasources_with_name[0].get("id")
        elif len(datasources_with_name) > 1 and p_name_or_luid is not False:
            if self.is_luid(p_name_or_luid):
                ds_in_proj = datasources.xpath(u'//t:project[@id="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            else:
                ds_in_proj = datasources.xpath(u'//t:project[@name="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            if len(ds_in_proj) == 0:
                self.end_log_block()
                raise NoMatchFoundException(u"No datasource found with name {} in project {}".format(name, p_name_or_luid))
            return ds_in_proj[0].get("id")
        # If no project is declared, and
        else:
            raise MultipleMatchesFoundException(u'More than one datasource found by name {} without a project specified'.format(name))

    def query_datasource_by_name_in_project(self, ds_name, p_name_or_luid=False):
        self.start_log_block()
        ds_luid = self.query_datasource_luid_by_name_in_project(ds_name, p_name_or_luid)
        ds = self.query_datasource_by_luid(ds_luid)
        self.end_log_block()
        return ds

    # Tries to guess name or LUID, including for the project. Better to use than just query_datasource
    def query_datasource_in_project(self, name_or_luid, p_name_or_luid):
        self.start_log_block()
        # LUID
        if self.is_luid(name_or_luid):
            ds = self.query_datasource_by_luid(name_or_luid)
        # Name
        else:
            ds = self.query_datasource_by_name_in_project(name_or_luid, p_name_or_luid)
        self.end_log_block()
        return ds

    # Tries to guess name or LUID, hope there is only one
    def query_datasource(self, name_or_luid):
        self.start_log_block()
        # LUID
        if self.is_luid(name_or_luid):
            ds = self.query_datasource_by_luid(name_or_luid)
        # Name
        else:
            ds = self.query_datasource_by_name_in_project(name_or_luid)
        self.end_log_block()
        return ds

    def query_datasources_in_project(self, project_name_or_luid):
        self.start_log_block()
        if self.is_luid(project_name_or_luid):
            project_luid = self.query_project_by_luid(project_name_or_luid)
        else:
            project_luid = self.query_project_luid_by_name(project_name_or_luid)
        datasources = self.query_datasources()
        # This brings back the datasource itself
        ds_in_project = datasources.xpath(u'//t:project[@id="{}"]/..'.format(project_luid), namespaces=self.__ns_map)
        self.end_log_block()
        return ds_in_project

    def query_datasource_permissions_by_luid(self, luid):
        self.start_log_block()
        ds_permissions = self.query_resource(u'datasources/{}/permissions'.format(luid))
        self.end_log_block()
        return ds_permissions

    # This is the best mix of flexibility and precision when called with a project name or luid
    def query_datasource_permissions_in_project(self, name_or_luid, p_name_or_luid=False):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            ds_permissions = self.query_datasource_permissions_by_luid(name_or_luid)
        else:
            ds_permissions = self.query_datasource_permissions_by_name_in_project(name_or_luid, p_name_or_luid)
        self.end_log_block()
        return ds_permissions

    # Preferrable to specify the project in case of multiples
    def query_datasource_permissions_by_name_in_project(self, name, p_name_or_luid=False):
        self.start_log_block()
        datasource_luid = self.query_datasource_luid_by_name_in_project(name, p_name_or_luid)
        ds_permissions = self.query_datasource_permissions_by_luid(datasource_luid)
        self.end_log_block()
        return ds_permissions

    # Not as good as query_datasource_permissions_by_name_in_project
    def query_datasource_permissions_by_name(self, name):
        self.start_log_block()
        datasource_luid = self.query_datasource_luid_by_name_in_project(name)
        ds_permissions = self.query_datasource_permissions_by_luid(datasource_luid)
        self.end_log_block()
        return ds_permissions

    # Not as good as query_datasource_permissions_in_project
    def query_datasource_permissions(self, name_or_luid, p_name_or_luid=False):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            ds_permissions = self.query_datasource_permissions_by_luid(name_or_luid)
        else:
            ds_permissions = self.query_datasource_permissions_by_name_in_project(name_or_luid, p_name_or_luid)
        self.end_log_block()
        return ds_permissions

    #
    # End Datasource Query Methods
    #

    #
    # Start Group Query Methods
    #

    def query_groups(self):
        self.start_log_block()
        groups = self.query_resource(u"groups")
        self.end_log_block()
        return groups

    # Simplest to use
    def query_group(self, name_or_luid):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            group = self.query_group_by_luid(name_or_luid)
        else:
            group = self.query_group_by_name(name_or_luid)
        self.end_log_block()
        return group

    # No basic verb for querying a single group, so run a query_groups
    def query_group_by_luid(self, group_luid):
        self.start_log_block()
        groups = self.query_groups()
        group = groups.xpath(u'//t:group[@id="{}"]'.format(group_luid), namespaces=self.__ns_map)
        if len(group) == 1:
            self.end_log_block()
            return group[0]
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"No group found with luid " + group_luid)

    # Groups luckily cannot have the same 'pretty name' on one site
    def query_group_luid_by_name(self, name):
        self.start_log_block()
        groups = self.query_groups()
        group = groups.xpath(u'//t:group[@name="{}"]'.format(name), namespaces=self.__ns_map)
        if len(group) == 1:
            self.end_log_block()
            return group[0].get("id")
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"No group found with name " + name)

    def query_group_by_name(self, name):
        self.start_log_block()
        group_luid = self.query_group_luid_by_name(name)
        group = self.query_group_by_luid(group_luid)
        self.end_log_block()
        return group

    #
    # End Group Querying methods
    #

    #
    # Start Project Querying methods
    #

    def query_projects(self):
        self.start_log_block()
        projects = self.query_resource(u"projects")
        self.end_log_block()
        return projects

    # Simplest to use
    def query_project(self, name_or_luid):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            project = self.query_project_by_luid(name_or_luid)
        else:
            project = self.query_project_by_name(name_or_luid)
        self.end_log_block()
        return project

    def query_project_by_luid(self, luid):
        self.start_log_block()
        projects = self.query_projects()
        project = projects.xpath(u'//t:project[@id="{}"]'.format(luid), namespaces=self.__ns_map)
        if len(project) == 1:
            self.end_log_block()
            return project[0]
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"No project found with luid " + luid)

    def query_project_luid_by_name(self, name):
        self.start_log_block()
        projects = self.query_projects()
        project = projects.xpath(u'//t:project[@name="{}"]'.format(name), namespaces=self.__ns_map)
        if len(project) == 1:
            self.end_log_block()
            return project[0].get("id")
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"No project found with name " + name)

    def query_project_by_name(self, name):
        self.start_log_block()
        luid = self.query_project_luid_by_name(name)
        project = self.query_project_by_luid(luid)
        self.end_log_block()
        return project

    # Simplest to use
    def query_project_permissions(self, name_or_luid):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            perms = self.query_project_permissions_by_luid(name_or_luid)
        else:
            perms = self.query_project_permissions_by_name(name_or_luid)
        self.end_log_block()
        return perms

    def query_project_permissions_by_luid(self, luid):
        self.start_log_block()
        perms = self.query_resource(u"projects/{}/permissions".format(luid))
        self.end_log_block()
        return perms

    def query_project_permissions_by_name(self, name):
        self.start_log_block()
        project_luid = self.query_project_luid_by_name(name)
        perms = self.query_project_permissions_by_luid(project_luid)
        self.end_log_block()
        return perms

    #
    # End Project Querying Methods
    #

    #
    # Start Site Querying Methods
    #

    # Site queries don't have the site portion of the URL, so login option gets correct format
    def query_sites(self):
        self.start_log_block()
        sites = self.query_resource(u"sites/", login=True)
        self.end_log_block()
        return sites

    # Methods for getting info about the sites, since you can only query a site when you are signed into it
    # Return list of all site luids

    def query_all_site_luids(self):
        self.start_log_block()
        sites = self.query_sites()
        site_luids = []
        for site in sites:
            site_luids.append(site.get("id"))
        self.end_log_block()
        return site_luids

    # Return list of all site contentUrls
    def query_all_site_content_urls(self):
        self.start_log_block()
        sites = self.query_sites()
        site_content_urls = []
        for site in sites:
            site_content_urls.append(site.get("contentUrl"))
        self.end_log_block()
        return site_content_urls

    # Return list of all site names
    def query_all_site_names(self):
        self.start_log_block()
        sites = self.query_sites()
        site_names = []
        for site in sites:
            site_names.append(site.get("name"))
        self.end_log_block()
        return site_names

    def query_site_luid_by_site_name(self, site_name):
        self.start_log_block()
        site_names = self.query_all_site_names()
        site_luids = self.query_all_site_luids()
        if site_name in site_names:
            self.end_log_block()
            return site_luids[site_names.index(site_name)]
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"Did not find site with name '{}' on the server".format(site_name))

    def query_site_luid_by_site_content_url(self, site_content_url):
        self.start_log_block()
        site_content_urls = self.query_all_site_content_urls()
        site_luids = self.query_all_site_luids()
        if site_content_url in site_content_urls:
            self.end_log_block()
            return site_luids[site_content_urls.index(site_content_url)]
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"Did not find site with ContentUrl '{}' on the server".format(site_content_url))

    def query_site_content_url_by_site_name(self, site_name):
        self.start_log_block()
        site_names = self.query_all_site_names()
        site_content_urls = self.query_all_site_content_urls()
        if site_name in site_names:
            self.end_log_block()
            return site_content_urls[site_names.index(site_name)]
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"Did not find site with name '{}' on the server".format(site_name))

    # You can only query a site you have logged into this way. Better to use methods that run through query_sites
    def query_current_site(self):
        self.start_log_block()
        site = self.query_resource(u"sites/" + self.__site_luid, login=True)
        self.end_log_block()
        return site

    #
    # End Site Querying Methods
    #

    #
    # Start User Querying Methods
    #

    def query_user_by_luid(self, luid):
        self.start_log_block()
        user = self.query_resource(u"users/{}".format(luid))
        self.end_log_block()
        return user

    def query_users(self):
        self.start_log_block()
        users = self.query_resource(u"users")
        self.log(u'Found {} users'.format(unicode(len(users))))
        self.end_log_block()
        return users

    def query_user_luid_by_username(self, username):
        self.start_log_block()
        users = self.query_users()
        user = users.xpath(u'//t:user[@name="{}"]'.format(username), namespaces=self.__ns_map)
        if len(user) == 1:
            self.end_log_block()
            return user[0].get("id")
        else:
            self.end_log_block()
            raise NoMatchFoundException(u"No user found with username {}".format(username))

    def query_users_in_group_by_luid(self, luid):
        self.start_log_block()
        users = self.query_resource(u"groups/{}/users".format(luid))
        self.end_log_block()
        return users

    def query_users_in_group_by_name(self, group_name):
        self.start_log_block()
        luid = self.query_group_luid_by_name(group_name)
        users = self.query_users_in_group_by_luid(luid)
        self.end_log_block()
        return users

    #
    # End User Querying Methods
    #

    #
    # Start Workbook Querying Methods
    #

    def query_workbook_by_luid(self, luid):
        self.start_log_block()
        workbook = self.query_resource(u"workbooks/{}".format(luid))
        self.end_log_block()
        return workbook

    def query_workbooks_for_user_by_luid(self, luid):
        self.start_log_block()
        workbooks = self.query_resource(u"users/{}/workbooks".format(luid))
        self.end_log_block()
        return workbooks

    # This uses the logged in username for convenience
    def query_workbooks(self):
        self.start_log_block()
        workbooks = self.query_workbooks_for_user_by_luid(self.__user_luid)
        self.end_log_block()
        return workbooks

    # Because a workbook can have the same pretty name in two projects, requires more logic
    def query_workbook_for_username_by_workbook_name_in_project(self, username, wb_name, p_name_or_luid=False):
        self.start_log_block()
        workbooks = self.query_workbooks_by_username(username)
        workbooks_with_name = workbooks.xpath(u'//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbooks_with_name) == 0:
            self.end_log_block()
            raise NoMatchFoundException(u"No workbook found for username '{}' named {}".format(username,wb_name))
        elif len(workbooks_with_name) == 1:
            wb_luid = workbooks_with_name[0].get("id")
            wb = self.query_workbook_by_luid(wb_luid)
            self.end_log_block()
            return wb
        elif len(workbooks_with_name) > 1 and p_name_or_luid is not False:
            if self.is_luid(p_name_or_luid):
                wb_in_proj = workbooks.xpath(u'//t:project[@id="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            else:
                wb_in_proj = workbooks.xpath(u'//t:project[@name="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            if len(wb_in_proj) == 0:
                self.end_log_block()
                raise NoMatchFoundException(u'No workbook found with name {} in project {}').format(wb_name, p_name_or_luid)
            wb_luid = wb_in_proj[0].get("id")
            wb = self.query_workbook_by_luid(wb_luid)
            self.end_log_block()
            return wb
        else:
            self.end_log_block()
            raise MultipleMatchesFoundException(u'More than one workbook found by name {} without a project specified').format(wb_name)

    # Less safe than _in_project method above
    def query_workbook_for_username_by_workbook_name(self, username, wb_name):
        self.start_log_block()
        workbook = self.query_workbook_for_username_by_workbook_name_in_project(username, wb_name)
        self.end_log_block()
        return workbook

    # Because a workbook can have the same pretty name in two projects, requires more logic
    def query_workbook_for_user_luid_by_workbook_name_in_project(self, user_luid, wb_name, p_name_or_luid=False):
        self.start_log_block()
        workbooks = self.query_workbooks_for_user_by_luid(user_luid)
        workbooks_with_name = workbooks.xpath(u'//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbooks_with_name) == 0:
            self.end_log_block()
            raise NoMatchFoundException(u"No workbook found for user luid '{}' named {}".format(user_luid, wb_name))
        elif len(workbooks_with_name) == 1:
            wb_luid = workbooks_with_name[0].get("id")
            wb = self.query_workbook_by_luid(wb_luid)
            self.end_log_block()
            return wb
        elif len(workbooks_with_name) > 1 and p_name_or_luid is not False:
            if self.is_luid(p_name_or_luid):
                wb_in_proj = workbooks.xpath(u'//t:project[@id="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            else:
                wb_in_proj = workbooks.xpath(u'//t:project[@name="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            if len(wb_in_proj) == 0:
                self.end_log_block()
                raise NoMatchFoundException(u'No workbook found with name {} in project {}').format(wb_name, p_name_or_luid)
            wb_luid = wb_in_proj[0].get("id")
            wb = self.query_workbook_by_luid(wb_luid)
            self.end_log_block()
            return wb
        else:
            self.end_log_block()
            raise MultipleMatchesFoundException(u'More than one workbook found by name {} without a project specified').format(wb_name)

    # Less safe than _in_project method above
    def query_workbook_for_user_luid_by_workbook_name(self, user_luid, wb_name):
        self.start_log_block()
        workbook = self.query_workbook_for_user_luid_by_workbook_name_in_project(user_luid, wb_name)
        self.end_log_block()
        return workbook

    def query_workbooks_in_project_for_username(self, project_name_or_luid, username):
        self.start_log_block()
        if self.is_luid(project_name_or_luid):
            project_luid = self.query_project_by_luid(project_name_or_luid)
        else:
            project_luid = self.query_project_luid_by_name(project_name_or_luid)
        workbooks = self.query_workbooks_by_username(username)
        # This brings back the workbook itself
        wbs_in_project = workbooks.xpath(u'//t:project[@id="{}"]/..'.format(project_luid), namespaces=self.__ns_map)
        self.end_log_block()
        return wbs_in_project

    def query_workbooks_in_project(self, project_name_or_luid):
        self.start_log_block()
        wbs = self.query_workbooks_in_project_for_username(project_name_or_luid, self.__username)
        self.end_log_block()
        return wbs

    # Assume the current logged in user
    def query_workbook_by_name_in_project(self, wb_name, p_name_or_luid=False):
        self.start_log_block()
        wb = self.query_workbook_for_user_luid_by_workbook_name_in_project(self.__user_luid, wb_name, p_name_or_luid)
        self.end_log_block()
        return wb

    # Less safe than _in_project method above
    def query_workbook_by_name(self, wb_name):
        self.start_log_block()
        wb = self.query_workbook_by_name_in_project(wb_name)
        self.end_log_block()
        return wb

    def query_workbook_luid_for_username_by_workbook_name_in_project(self, username, wb_name, p_name_or_luid=False):
        self.start_log_block()
        workbooks = self.query_workbooks_by_username(username)
        workbooks_with_name = workbooks.xpath(u'//t:workbook[@name="{}"]'.format(wb_name), namespaces=self.__ns_map)
        if len(workbooks_with_name) == 0:
            self.end_log_block()
            raise NoMatchFoundException(u"No workbook found for username '{}' named {}".format(username, wb_name))
        elif len(workbooks_with_name) == 1:
            wb_luid = workbooks_with_name[0].get("id")
            self.end_log_block()
            return wb_luid
        elif len(workbooks_with_name) > 1 and p_name_or_luid is not False:
            if self.is_luid(p_name_or_luid):
                wb_in_proj = workbooks.xpath(u'//t:project[@id="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            else:
                wb_in_proj = workbooks.xpath(u'//t:project[@name="{}"]/..'.format(p_name_or_luid), namespaces=self.__ns_map)
            if len(wb_in_proj) == 0:
                self.end_log_block()
                raise NoMatchFoundException(u'No workbook found with name {} in project {}').format(wb_name, p_name_or_luid)
            wb_luid = wb_in_proj[0].get("id")
            self.end_log_block()
            return wb_luid
        else:
            self.end_log_block()
            raise MultipleMatchesFoundException(u'More than one workbook found by name {} without a project specified').format(wb_name)

    # Less safe than _in_project method above
    def query_workbook_luid_for_username_by_workbook_name(self, username, wb_name):
        self.start_log_block()
        luid = self.query_workbook_luid_for_username_by_workbook_name_in_project(username, wb_name)
        self.end_log_block()
        return luid

    def query_workbooks_by_username(self, username):
        self.start_log_block()
        user_luid = self.query_user_luid_by_username(username)
        wbs = self.query_workbooks_for_user_by_luid(user_luid)
        self.end_log_block()
        return wbs

    # Used the logged in username
    def query_workbook_views_by_workbook_name_in_project(self, wb_name, usage=False, p_name_or_luid=False):
        self.start_log_block()
        wb_luid = self.query_workbook_luid_for_username_by_workbook_name_in_project(self.__username, wb_name, p_name_or_luid)
        vws = self.query_workbook_views_by_luid(wb_luid, usage)
        self.end_log_block()
        return vws

    # Less safe than _in_project method above
    def query_workbook_views_by_workbook_name(self, wb_name, usage=False):
        self.start_log_block()
        vws = self.query_workbook_views_by_workbook_name_in_project(wb_name, usage)
        self.end_log_block()
        return vws

    # Set Usage to True to get usage with this
    def query_workbook_views_by_luid(self, wb_luid, usage=False):
        self.start_log_block()
        if usage not in [True, False]:
            raise InvalidOptionException(u'Usage can only be set to True or False')
        vws = self.query_resource(u"workbooks/{}/views?includeUsageStatistics={}".format(wb_luid, str(usage).lower()))
        self.end_log_block()
        return vws

    def query_workbook_permissions_by_luid(self, wb_luid):
        self.start_log_block()
        perms = self.query_resource(u"workbooks/{}/permissions".format(wb_luid))
        self.end_log_block()
        return perms

    def query_workbook_permissions_for_username_by_workbook_name_in_project(self, username, wb_name, p_name_or_luid=False):
        self.start_log_block()
        wb_luid = self.query_workbook_luid_for_username_by_workbook_name_in_project(username, wb_name, p_name_or_luid)
        perms = self.query_workbook_permissions_by_luid(wb_luid)
        self.end_log_block()
        return perms

    # Less safe than _in_project method above
    def query_workbook_permissions_for_username_by_workbook_name(self, username, wb_name):
        self.start_log_block()
        perms = self.query_workbook_permissions_for_username_by_workbook_name_in_project(username, wb_name)
        self.end_log_block()
        return perms

    def query_workbook_permissions_in_project(self, name_or_luid, p_name_or_luid=False):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            perms = self.query_workbook_permissions_by_luid(name_or_luid)
        else:
            perms = self.query_workbook_permissions_for_username_by_workbook_name_in_project(self.__username, p_name_or_luid)
        self.end_log_block()
        return perms

    # Less safe than the _in_project method above
    def query_workbook_permissions(self, name_or_luid):
        self.start_log_block()
        perms = self.query_workbook_permissions_in_project(name_or_luid)
        self.end_log_block()
        return perms

    def query_workbook_connections_by_luid(self, wb_luid):
        self.start_log_block()
        conns = self.query_resource(u"workbooks/{}/connections".format(wb_luid))
        self.end_log_block()
        return conns

    # This should be the key to updating the connections in a workbook. Seems to return
    # LUIDs for connections and the datatypes, but no way to distinguish them
    def query_workbook_connections_for_username_by_workbook_name_in_project(self, username, wb_name, p_name_or_luid=False):
        self.start_log_block()
        wb_luid = self.query_workbook_for_username_by_workbook_name_in_project(username, wb_name, p_name_or_luid)
        self.end_log_block()
        conns = self.query_workbook_connections_by_luid(wb_luid)
        return conns

    # Checks status of AD sync process
    def query_job_by_luid(self, job_luid):
        self.start_log_block()
        job = self.query_resource(u"jobs/{}".format(job_luid))
        self.end_log_block()
        return job

    #
    # End Workbook Query Methods
    #

    #
    # Start of download / save methods
    #

    # Do not include file extension
    def save_workbook_view_preview_image_by_luid(self, wb_luid, view_luid, filename):
        self.start_log_block()
        try:
            save_file = open(filename + ".png", 'wb')
            url = self.build_api_url(u"workbooks/{}/views/{}/previewImage".format(wb_luid, view_luid))
            image = self.send_binary_get_request(url)
            save_file.write(image)
            save_file.close()
            self.end_log_block()

        # You might be requesting something that doesn't exist
        except RecoverableHTTPException as e:
            self.log(u"Attempt to request preview image results in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            self.end_log_block()
            raise
        except IOError:
            self.log(u"Error: File '{}' cannot be opened to save to".format(filename))
            self.end_log_block()
            raise

    # Do not include file extension
    def save_workbook_preview_image_by_luid(self, wb_luid, filename):
        self.start_log_block()
        try:
            save_file = open(filename + '.png', 'wb')
            url = self.build_api_url(u"workbooks/{}/previewImage".format(wb_luid))
            image = self.send_binary_get_request(url)
            save_file.write(image)
            save_file.close()
            self.end_log_block()

        # You might be requesting something that doesn't exist, but unlikely
        except RecoverableHTTPException as e:
            self.log(u"Attempt to request preview image results in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            self.end_log_block()
            raise
        except IOError:
            self.log(u"Error: File '{}' cannot be opened to save to".format(filename))
            self.end_log_block()
            raise

    # Do not include file extension. Without filename, only returns the response
    def download_datasource_by_luid(self, ds_luid, filename=None):
        self.start_log_block()
        try:
            url = self.build_api_url(u"datasources/{}/content".format(ds_luid))
            ds = self.send_binary_get_request(url)
            extension = None
            if self.__last_response_content_type.find(u'application/xml') != -1:
                extension = u'.tds'
            elif self.__last_response_content_type.find(u'application/octet-stream') != -1:
                extension = u'.tdsx'
            if extension is None:
                raise IOError(u'File extension could not be determined')
        except RecoverableHTTPException as e:
            self.log(u"download_datasource_by_luid resulted in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            self.end_log_block()
            raise
        except:
            self.end_log_block()
            raise
        try:
            if filename is None:
                save_filename = 'temp_ds' + extension
            else:
                save_filename = filename + extension
            save_file = open(save_filename, 'wb')
            save_file.write(ds)
            save_file.close()
            if extension == u'.tdsx':
                self.log(u'Detected TDSX, creating TableauPackagedFile object')
                saved_file = open(save_filename, 'rb')
                return_obj = TableauPackagedFile(saved_file, self.logger)
                saved_file.close()
                if filename is None:
                    os.remove(save_filename)
        except IOError:
            self.log(u"Error: File '{}' cannot be opened to save to".format(filename + extension))
            raise
        if extension == '.tds':
            self.log(u'Detected TDS, creating TableauDatasource object')
            return_obj = TableauDatasource(ds, self.logger)

        self.end_log_block()
        return return_obj

    # Do not include file extension, added automatically. Without filename, only returns the response
    # Use no_obj_return for save without opening and processing
    def download_workbook_by_luid(self, wb_luid, filename=None, no_obj_return=False):
        self.start_log_block()
        try:
            url = self.build_api_url(u"workbooks/{}/content".format(wb_luid))
            wb = self.send_binary_get_request(url)
            extension = None
            if self.__last_response_content_type.find(u'application/xml') != -1:
                extension = u'.twb'
            elif self.__last_response_content_type.find(u'application/octet-stream') != -1:
                extension = u'.twbx'
            if extension is None:
                raise IOError(u'File extension could not be determined')
        except RecoverableHTTPException as e:
            self.log(u"download_workbook_by_luid resulted in HTTP error {}, Tableau Code {}".format(e.http_code, e.tableau_error_code))
            self.end_log_block()
            raise
        except:
            self.end_log_block()
            raise
        try:
            if filename is None:
                save_filename = 'temp_wb' + extension
            else:
                save_filename = filename + extension

            save_file = open(save_filename, 'wb')
            save_file.write(wb)
            save_file.close()
            if no_obj_return is True:
                return
            if extension == u'.twbx':
                self.log(u'Detected TWBX, creating TableauPackagedFile object')
                saved_file = open(save_filename, 'rb')
                return_obj = TableauPackagedFile(saved_file, self.logger)
                if filename is None:
                    os.remove(save_filename)

        except IOError:
            self.log(u"Error: File '{}' cannot be opened to save to".format(filename + extension))
            raise
        if no_obj_return is True:
            return
        if extension == u'.twb':
            self.log(u'Detected TWB, creating TableauWorkbook object')
            return_obj = TableauWorkbook(wb, self.logger)
        self.end_log_block()
        return return_obj

    #
    # End download / save methods
    #

    #
    # Create / Add Methods
    #

    def add_user_by_username(self, username, site_role=u'Unlicensed', update_if_exists=False):
        self.start_log_block()
        # Check to make sure role that is passed is a valid role in the API
        try:
            self.__site_roles.index(site_role)
        except:
            raise InvalidOptionException(u"{} is not a valid site role in Tableau Server".format(site_role))

        self.log(u"Adding {}".format(username))
        add_request = u'<tsRequest><user name="{}" siteRole="{}" /></tsRequest>'.format(username, site_role)
        url = self.build_api_url(u'users')
        try:
            new_user = self.send_add_request(url, add_request)
            new_user_luid = new_user.xpath(u'//t:user', namespaces=self.__ns_map)[0].get("id")
            self.end_log_block()
            return new_user_luid
        # If already exists, update site role unless overridden.
        except RecoverableHTTPException as e:
            if e.http_code == 409:
                self.log(u"Username '{}' already exists on the server".format(username))
                if update_if_exists is True:
                    self.log(u'Updating {} to site role {}'.format(username, site_role))
                    self.update_user(username, site_role=site_role)
                    self.end_log_block()
                    return self.query_user_luid_by_username(username)
                else:
                    self.end_log_block()
                    raise AlreadyExistsException(u'Username already exists ', self.query_user_luid_by_username(username))
        except:
            self.end_log_block()
            raise

    # This is "Add User to Site", since you must be logged into a site.
    # Set "update_if_exists" to True if you want the equivalent of an 'upsert', ignoring the exceptions
    def add_user(self, username, fullname, site_role=u'Unlicensed', password=None, email=None, update_if_exists=False):
        self.start_log_block()
        try:
            # Add username first, then update with full name
            new_user_luid = self.add_user_by_username(username, site_role=site_role, update_if_exists=update_if_exists)
            self.update_user_by_luid(new_user_luid, fullname, site_role, password, email)
            self.end_log_block()
            return new_user_luid
        except AlreadyExistsException as e:
            self.log(u"Username '{}' already exists on the server; no updates performed".format(username))
            self.end_log_block()
            return e.existing_luid

    # Returns the LUID of an existing group if one already exists
    def create_group(self, group_name):
        self.start_log_block()
        add_request = u'<tsRequest><group name="{}" /></tsRequest>'.format(group_name)
        self.log(u'Creating a group using the following XML: {}'.format(add_request))
        url = self.build_api_url(u"groups")
        self.log(u'Sending create group request via {}'.format(url))
        try:
            new_group = self.send_add_request(url, add_request)
            self.end_log_block()
            return new_group.xpath(u'//t:group', namespaces=self.__ns_map)[0].get("id")
        # If the name already exists, a HTTP 409 throws, so just find and return the existing LUID
        except RecoverableHTTPException as e:
            if e.http_code == 409:
                self.log(u'Group named {} already exists, finding and returning the LUID'.format(group_name))
                self.end_log_block()
                return self.query_group_luid_by_name(group_name)

    # Creating a synced ad group is completely different, use this method
    # The luid is only available in the Response header if bg sync. Nothing else is passed this way -- how to expose?
    def create_group_from_ad_group(self, ad_group_name, ad_domain_name, default_site_role=u'Unlicensed',
                                   sync_as_background=True):
        self.start_log_block()
        if default_site_role not in self.__site_roles:
            raise InvalidOptionException(u'"{}" is not an acceptable site role'.format(default_site_role))
        add_request = u'<tsRequest><group name="{}">'.format(ad_group_name)
        add_request += u'<import source="ActiveDirectory" domainName="{}" siteRole="{}" />'.format(ad_domain_name,
                                                                                                  default_site_role)
        add_request += u'</group></tsRequest>'
        self.log(add_request)
        url = self.build_api_url(u"groups/?asJob={}".format(str(sync_as_background).lower()))
        self.log(url)
        response = self.send_add_request(url, add_request)
        # Response is different from immediate to background update. job ID lets you track progress on background
        if sync_as_background is True:
            job = response.xpath(u'//t:job', namespaces=self.__ns_map)
            self.end_log_block()
            return job[0].get('id')
        if sync_as_background is False:
            self.end_log_block()
            group = response.xpath(u'//t:group', namespaces=self.__ns_map)
            return group[0].get('id')

    def create_project(self, project_name, project_desc=None):
        self.start_log_block()
        add_request = u'<tsRequest><project name="{}" '.format(project_name)
        if project_desc is not None:
            add_request += u'description="{}"'.format(project_desc)
        add_request += u" /></tsRequest>"
        self.log(add_request)
        url = self.build_api_url(u"projects")
        try:
            new_project = self.send_add_request(url, add_request)
            self.end_log_block()
            return new_project.xpath(u'//t:project', namespaces=self.__ns_map)[0].get("id")
        except RecoverableHTTPException as e:
            if e.http_code == 409:
                self.log(u'Project named {} already exists, finding and returning the LUID'.format(project_name))
                self.end_log_block()
                return self.query_project_luid_by_name(project_name)

    # Both SiteName and ContentUrl must be unique to add a site
    # FIX TO NOT BE SO HEAVY AND JUST LOOK FOR HTTP ERRORS
    def create_site(self, new_site_name, new_content_url, admin_mode=None, user_quota=None, storage_quota=None,
                    disable_subscriptions=None):
        # Both SiteName and ContentUrl must be unique to add a site
        self.log(u'Querying all of the site names prior to create')
        site_names = self.query_all_site_names()
        site_names_lc = []
        self.log(u'Attempting to create site "{}" with content_url "{}"'.format(new_site_name, new_content_url))
        for name in site_names:
            site_names_lc.append(name.lower())

        if new_site_name.lower() in site_names_lc:
            raise AlreadyExistsException(u"Site Name '" + new_site_name + u"' already exists on server", new_site_name)
        site_content_urls = self.query_all_site_content_urls()
        if new_content_url in site_content_urls:
            raise AlreadyExistsException(u"Content URL '{}' already exists on server".format(new_content_url),
                                         new_content_url)
        add_request = self.__build_site_request_xml(new_site_name, new_content_url, admin_mode, user_quota,
                                                    storage_quota, disable_subscriptions)
        url = self.build_api_url(u"sites/", login=True)  # Site actions drop back out of the site ID hierarchy like login
        self.log(u'Creating a site using the following XML: {}'.format(add_request))
        self.log(u'Sending create request via: {}'.format(url))
        new_site = self.send_add_request(url, add_request)
        return new_site.xpath(u'//t:site', namespaces=self.__ns_map)[0].get("id")

    # Take a single user_luid string or a collection of luid_strings
    def add_users_to_group_by_luid(self, user_luid_s, group_luid):
        self.start_log_block()
        user_luids = self.to_list(user_luid_s)
        for user_luid in user_luids:
            add_request = u'<tsRequest><user id="{}" /></tsRequest>'.format(user_luid)
            self.log(u'Attempingt to add user with following XML: {}'.format(add_request))
            url = self.build_api_url(u"groups/{}/users/".format(group_luid))
            self.log(u'Sending add request via: {}'.format(url))
            try:
                self.send_add_request(url, add_request)
                self.end_log_block()
            except RecoverableHTTPException as e:
                self.log(u"Recoverable HTTP exception {} with Tableau Error Code {}, skipping".format(str(e.http_code), e.tableau_error_code))
                self.end_log_block()

    # Tags can be scalar string or list
    def add_tags_to_workbook_by_luid(self, wb_luid, tag_s):
        self.start_log_block()
        url = self.build_api_url(u"workbooks/{}/tags".format(wb_luid))
        request = u"<tsRequest><tags>"
        tags = self.to_list(tag_s)
        for tag in tags:
            request += u"<tag label='{}' />".format(str(tag))
        request += u"</tags></tsRequest>"
        tag_response = self.send_update_request(url, request)
        self.end_log_block()
        return tag_response

    def add_workbook_to_user_favorites_by_luid(self, favorite_name, wb_luid, user_luid):
        self.start_log_block()
        request = u'<tsRequest><favorite label="{}"><workbook id="{}" />'.format(favorite_name, wb_luid)
        request += u'</favorite></tsRequest>'
        url = self.build_api_url(u"favorites/{}".format(user_luid))
        update_response = self.send_update_request(url, request)
        self.end_log_block()
        return update_response

    def add_view_to_user_favorites_by_luid(self, favorite_name, view_luid, user_luid):
        self.start_log_block()
        request = u'<tsRequest><favorite label="{}"><view id="{}" />'.format(favorite_name, view_luid)
        request += u'</favorite></tsRequest>'
        url = self.build_api_url(u"favorites/{}".format(user_luid))
        update_response = self.send_update_request(url, request)
        self.end_log_block()
        return update_response

    # Add dict { capability_name : capability_mode } 'Allow' or 'Deny'
    # Assumes group because you should be doing all your security by groups instead of individuals
    def add_permissions_by_luids(self, obj_type, obj_luid_s, luid_s, permissions_dict, luid_type='group'):
        if luid_type not in ['group', 'user']:
            raise InvalidOptionException(u"luid_type can only be 'group' or 'user'")
        if obj_type not in self.__permissionable_objects:
            raise InvalidOptionException(u'obj_type must be "workbook","datasource" or "project"')

        luids = self.to_list(luid_s)
        obj_luids = self.to_list(obj_luid_s)

        self.log(permissions_dict)
        capabilities_xml = self.build_capabilities_xml_from_dict(permissions_dict, obj_type)
        for obj_luid in obj_luids:
            request = u"<tsRequest><permissions><{} id='{}' />".format(obj_type, obj_luid)
            for luid in luids:
                request += u"<granteeCapabilities><{} id='{}' />".format(luid_type, luid)
                request += capabilities_xml
                request += u"</granteeCapabilities>"
            request += u"</permissions></tsRequest>"
            url = self.build_api_url(u"{}s/{}/permissions".format(obj_type, obj_luid))
            self.send_update_request(url, request)

    def add_permissions_by_gcap_obj_list(self, obj_type, obj_luid_s, gcap_obj_list):
        if obj_type not in self.__permissionable_objects:
            raise InvalidOptionException(u'obj_type must be "workbook","datasource" or "project"')

        obj_luids = self.to_list(obj_luid_s)

        for obj_luid in obj_luids:
            request = u"<tsRequest><permissions><{} id='{}' />".format(obj_type, obj_luid)
            for gcap_obj in gcap_obj_list:
                gcap_luid = gcap_obj.get_luid()
                gcap_obj_type = gcap_obj.get_obj_type()
                capabilities_dict = gcap_obj.get_capabilities_dict()
                capabilities_xml = self.build_capabilities_xml_from_dict(capabilities_dict, obj_type)
                request += u"<granteeCapabilities><{} id='{}' />".format(gcap_obj_type, gcap_luid)
                request += capabilities_xml
                request += u"</granteeCapabilities>"
            request += u"</permissions></tsRequest>"
            url = self.build_api_url(u"{}s/{}/permissions".format(obj_type, obj_luid))
            self.send_update_request(url, request)

    #
    # End Add methods
    #

    #
    # Start Update Methods
    #

    # Simplest method
    def update_user(self, username_or_luid, full_name=None, site_role=None, password=None,
                    email=None):
        self.start_log_block()
        if self.is_luid(username_or_luid):
            response = self.update_user_by_luid(username_or_luid, full_name, site_role, password, email)
        else:
            response = self.update_user_by_username(username_or_luid, full_name, site_role, password, email)
        self.end_log_block()
        return response

    def update_user_by_luid(self, user_luid, full_name=None, site_role=None, password=None,
                            email=None):
        self.start_log_block()
        update_request = u"<tsRequest><user "
        if full_name is not None:
            update_request += u'fullName="{}" '.format(full_name)
        if site_role is not None:
            update_request += u'siteRole="{}" '.format(site_role)
        if email is not None:
            update_request += u'email="{}" '.format(email)
        if password is not None:
            update_request += u'password="{}" '.format(password)
        update_request += u"/></tsRequest>"
        url = self.build_api_url(u"users/{}".format(user_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    def update_user_by_username(self, username, full_name=None, site_role=None, password=None,
                                email=None):
        self.start_log_block()
        user_luid = self.query_user_luid_by_username(username)
        response = self.update_user_by_luid(user_luid, full_name, site_role, password, email)
        self.end_log_block()
        return response

    def update_datasource_by_luid(self, datasource_luid, new_datasource_name=None, new_project_luid=None,
                                  new_owner_luid=None):
        self.start_log_block()
        update_request = u"<tsRequest><datasource"
        if new_datasource_name is not None:
            update_request = update_request + u' name="{}" '.format(new_datasource_name)
        update_request += u">"  # Complete the tag no matter what
        if new_project_luid is not None:
            update_request += u'<project id="{}"/>'.format(new_project_luid)
        if new_owner_luid is not None:
            update_request += u'<owner id="{}"/>'.format(new_owner_luid)
        update_request += u"</datasource></tsRequest>"
        url = self.build_api_url(u"datasources/{}".format(datasource_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    # Need to specify project because datasource 'pretty names' can be identical, as long as in different projects
    def update_datasource_by_name_in_project(self, datasource_name, new_datasource_name=None, new_project_luid=None,
                                             new_owner_luid=None, proj_name_or_luid=False):
        self.start_log_block()
        ds_luid = self.query_datasource_luid_by_name_in_project(datasource_name, proj_name_or_luid)
        response = self.update_datasource_by_luid(ds_luid, new_datasource_name, new_project_luid, new_owner_luid)
        self.end_log_block()
        return response

    # If going by name, you should specify the project in case there are matches
    def update_datasource(self, name_or_luid, new_datasource_name=None, new_project_luid=None,
                          new_owner_luid=None, proj_name_or_luid=False):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            response = self.update_datasource_by_luid(name_or_luid, new_datasource_name, new_project_luid, new_owner_luid)
        else:
            response = self.update_datasource_by_name_in_project(name_or_luid, new_datasource_name, new_project_luid,
                                                                 new_owner_luid, proj_name_or_luid=proj_name_or_luid)
        self.end_log_block()
        return response

    def update_datasource_connection_by_luid(self, datasource_luid, new_server_address=None, new_server_port=None,
                                             new_connection_username=None, new_connection_password=None):
        self.start_log_block()
        update_request = self.__build_connection_update_xml(new_server_address, new_server_port,
                                                            new_connection_username,
                                                            new_connection_password)
        url = self.build_api_url(u"datasources/{}/connection".format(datasource_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    # Local Authentication update group

    # Simplest method
    def update_group(self, name_or_luid, new_group_name):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            response = self.update_group_by_luid(name_or_luid, new_group_name)
        else:
            response = self.update_group_by_name(name_or_luid, new_group_name)
        self.end_log_block()
        return response

    def update_group_by_luid(self, group_luid, new_group_name):
        self.start_log_block()
        # Check that group_luid exists
        self.query_group_by_luid(group_luid)
        update_request = u'<tsRequest><group name="{}" /></tsRequest>'.format(new_group_name)
        url = self.build_api_url(u"groups/{}".format(group_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    def update_group_by_name(self, name, new_group_name):
        self.start_log_block()
        group_luid = self.query_group_luid_by_name(name)
        response = self.update_group_by_luid(group_luid, new_group_name)
        self.end_log_block()
        return response

    # AD group sync. Must specify the domain and the default site role for imported users
    def sync_ad_group_by_luid(self, group_luid, ad_group_name, ad_domain, default_site_role, sync_as_background=True):
        self.start_log_block()
        if sync_as_background not in [True, False]:
            error = u"'{}' passed for sync_as_background. Use True or False".format(str(sync_as_background).lower())
            raise InvalidOptionException(error)

        if default_site_role not in self.__site_roles:
            raise InvalidOptionException(u"'{}' is not a valid site role in Tableau".format(default_site_role))
        # Check that the group exists
        self.query_group_by_luid(group_luid)
        request = u'<tsRequest><group name="{}">'.format(ad_group_name)
        request += u'<import source="ActiveDirectory" domainName="{}" siteRole="{}" />'.format(ad_domain,
                                                                                              default_site_role)
        request += u'</group></tsRequest>'
        url = self.build_api_url(u"groups/{}".format(group_luid) + u"?asJob={}".format(unicode(sync_as_background)).lower())
        response = self.send_update_request(url, request)
        # Response is different from immediate to background update. job ID lets you track progress on background
        if sync_as_background is True:
            job = response.xpath(u'//t:job', namespaces=self.__ns_map)
            self.end_log_block()
            return job[0].get('id')
        if sync_as_background is False:
            group = response.xpath(u'//t:group', namespaces=self.__ns_map)
            self.end_log_block()
            return group[0].get('id')

    # Simplest method
    def update_project(self, name_or_luid, new_project_name=None, new_project_description=None):
        self.start_log_block()
        if self.is_luid(name_or_luid):
            response = self.update_project_by_luid(name_or_luid, new_project_name, new_project_description)
        else:
            response = self.update_project_by_name(name_or_luid, new_project_name, new_project_description)
        self.end_log_block()
        return response

    def update_project_by_luid(self, project_luid, new_project_name=None, new_project_description=None):
        self.start_log_block()
        update_request = u'<tsRequest><project '
        if new_project_name is not None:
            update_request += u'name="{}" '.format(new_project_name)
        if new_project_description is not None:
            update_request += u'description="{}"'.format(new_project_description)
        update_request += u"/></tsRequest>"
        self.log(update_request)
        url = self.build_api_url(u"projects/{}".format(project_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    def update_project_by_name(self, project_name, new_project_name=None, new_project_description=None):
        self.start_log_block()
        project_luid = self.query_project_luid_by_name(project_name)
        response = self.update_project_by_luid(project_luid, new_project_name, new_project_description)
        self.end_log_block()
        return response

    # Can only update the site you are signed into, so take site_luid from the object
    def update_current_site(self, site_name=None, content_url=None, admin_mode=None, user_quota=None,
                            storage_quota=None, disable_subscriptions=None, state=None):
        self.start_log_block()
        update_request = self.__build_site_request_xml(site_name, content_url, admin_mode, user_quota, storage_quota,
                                                       disable_subscriptions, state)
        url = self.build_api_url(u"/")
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    def update_workbook_by_luid(self, workbook_luid, new_project_luid=None, new_owner_luid=None, show_tabs=None):
        self.start_log_block()
        update_request = u"<tsRequest><workbook showTabs='{}'>".format(str(show_tabs).lower())
        if new_project_luid is not None:
            update_request += u'<project id="{}" />'.format(new_project_luid)
        if new_owner_luid is not None:
            update_request += u'<owner id="{}" />'.format(new_owner_luid)
        update_request += u'</workbook></tsRequest>'
        url = self.build_api_url(u"workbooks/{}".format(workbook_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    # To do this, you need the workbook's connection_luid. Seems to only come from "Query Workbook Connections",
    # which does not return any names, just types and LUIDs
    def update_workbook_connection_by_luid(self, wb_luid, connection_luid, new_server_address=None,
                                           new_server_port=None,
                                           new_connection_username=None, new_connection_password=None):
        self.start_log_block()
        update_request = self.__build_connection_update_xml(new_server_address, new_server_port,
                                                            new_connection_username,
                                                            new_connection_password)
        url = self.build_api_url(u"workbooks/{}/connections/{}".format(wb_luid, connection_luid))
        response = self.send_update_request(url, update_request)
        self.end_log_block()
        return response

    # Creates a single XML block based on capabilities_dict that is passed in
    # Capabilities dict like { capName : 'Allow', capName : 'Deny'...}

    # Can take single group_luid or list and will assign the same capabilities to each group sent in
    # The essence of this update is that we delete the capabilities, then add them back as we want
    def update_permissions_by_luids(self, obj_type, obj_luid_s, luid_s, permissions_dict, luid_type='group'):
        self.start_log_block()
        obj_luids = self.to_list(obj_luid_s)
        luids = self.to_list(luid_s)
        if obj_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException(u'obj_type must be "project", "datasource" or "workbook"')
        # Do this object by object, so that the delete and the assign are all together
        self.log(u'Updating permissions for {} LUIDs'.format(unicode(len(obj_luids))))
        for obj_luid in obj_luids:
            try:
                self.log(u'Deleting all permissions for {}'.format(obj_luid))
                self.delete_all_permissions_by_luids(obj_type.lower(), obj_luid, luids)
            except InvalidOptionException as e:
                self.log(e.msg)
                raise
            self.add_permissions_by_luids(obj_type.lower(), obj_luid, luids, permissions_dict, luid_type)
        self.end_log_block()

    def update_permissions_by_gcap_obj_list(self, obj_type, obj_luid_s, gcap_obj_list):
        self.start_log_block()
        obj_luids = self.to_list(obj_luid_s)
        if obj_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException(u'obj_type must be "project", "datasource" or "workbook"')
        # Do this object by object, so that the delete and the assign are all together
        gcap_luids = []
        for gcap_obj in gcap_obj_list:
            gcap_luids.append(gcap_obj.get_luid())
        self.log(u'Updating permissions for {} LUIDs'.format(unicode(len(obj_luids))))
        for obj_luid in obj_luids:
            # Depending on object type, we have to do the method to get our permissions
            if obj_type == u'project':
                permissions_lxml = self.query_project_permissions(obj_luid)
            elif obj_type == u'datasource':
                permissions_lxml = self.query_datasource_permissions(obj_luid)
            elif obj_type == u'workbook':
                permissions_lxml = self.query_workbook_permissions_by_luid(obj_luid)
            else:
                raise InvalidOptionException(u'obj_type not set correctly')
            try:
                dest_capabilities_list = self.convert_capabilities_xml_into_obj_list(permissions_lxml)

                if self.are_capabilities_objs_identical_for_matching_luids(gcap_obj_list, dest_capabilities_list) is False:
                    try:
                        self.log(u'Deleting all permissions for {}'.format(obj_luid))
                        self.delete_all_permissions_by_luids(obj_type.lower(), obj_luid, gcap_luids)
                    except InvalidOptionException as e:
                        self.log(e.msg)
                        raise
                    self.add_permissions_by_gcap_obj_list(obj_type.lower(), obj_luid, gcap_obj_list)
                else:
                    self.log(u'Skipping update because permissions on object {} already match'.format(obj_luid))
            # If there are no permissions at all, just set whatever was sent
            except NoMatchFoundException:
                self.add_permissions_by_gcap_obj_list(obj_type.lower(), obj_luid, gcap_obj_list)
        self.end_log_block()

    # Special permissions methods
    # Take the permissions from one object (project most likely) and assign to other content
    # Requires clearing all permissions on an object
    def replicate_content_permissions(self, obj_luid, obj_type, dest_luid_s, dest_type):
        self.start_log_block()
        dest_obj_luids = self.to_list(dest_luid_s)
        if obj_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException(u'obj_type must be "project", "datasource" or "workbook"')
        if dest_type.lower() not in self.__permissionable_objects:
            raise InvalidOptionException(u'dest_type must be "project", "datasource" or "workbook"')
        # Depending on object type, we have to do the method to get our permissions
        if obj_type == u'project':
            permissions_lxml = self.query_project_permissions(obj_luid)
        elif obj_type == u'datasource':
            permissions_lxml = self.query_datasource_permissions(obj_luid)
        elif obj_type == u'workbook':
            permissions_lxml = self.query_workbook_permissions_by_luid(obj_luid)
        else:
            raise InvalidOptionException(u'obj_type not set correctly')

        capabilities_list = self.convert_capabilities_xml_into_obj_list(permissions_lxml)
        for dest_obj_luid in dest_obj_luids:
            # Grab the destination permissions too, so we can compare and skip if already identical
            if dest_type == u'project':
                dest_permissions_lxml = self.query_project_permissions(dest_obj_luid)
            elif dest_type == u'datasource':
                dest_permissions_lxml = self.query_datasource_permissions(dest_obj_luid)
            elif dest_type == u'workbook':
                dest_permissions_lxml = self.query_workbook_permissions_by_luid(dest_obj_luid)
            else:
                raise InvalidOptionException(u'obj_type not set correctly')
            dest_capabilities_list = self.convert_capabilities_xml_into_obj_list(dest_permissions_lxml)
            if self.are_capabilities_obj_lists_identical(capabilities_list, dest_capabilities_list) is False:
                # Delete all first clears the object to have them added
                self.delete_all_permissions_by_luids(dest_type, dest_obj_luid)
                # Add each set of capabilities to the cleared object
                self.add_permissions_by_gcap_obj_list(dest_type, dest_obj_luid, capabilities_list)
            else:
                self.log(u"Permissions matched, no need to update. Moving to next")
        self.end_log_block()

    # Pulls the permissions from the project, then applies them to all the content in the project
    def sync_project_permissions_to_contents(self, project_name_or_luid):
        self.start_log_block()
        if self.is_luid(project_name_or_luid):
            project_luid = project_name_or_luid
        else:
            project_luid = self.query_project_luid_by_name(project_name_or_luid)
        wbs_in_project = self.query_workbooks_in_project(project_name_or_luid)
        datasources_in_project = self.query_datasources_in_project(project_name_or_luid)
        self.log(u'Replicating permissions down to workbooks')
        wb_dict = self.convert_xml_list_to_name_id_dict(wbs_in_project)
        self.replicate_content_permissions(project_luid, 'project', wb_dict.values(), 'workbook')
        self.log(u'Replicating permissions down to datasource')
        ds_dict = self.convert_xml_list_to_name_id_dict(datasources_in_project)
        self.replicate_content_permissions(project_luid, 'project', ds_dict.values(), 'datasource')
        self.end_log_block()
    #
    # End Permissions Methods
    #

    #
    # Start Delete methods
    #

    # Can take collection or luid_string
    def delete_datasources_by_luid(self, datasource_luid_s):
        self.start_log_block()
        datasource_luids = self.to_list(datasource_luid_s)
        for datasource_luid in datasource_luids:
            url = self.build_api_url(u"datasources/{}".format(datasource_luid))
            self.send_delete_request(url)
        self.end_log_block()

    def delete_projects_by_luid(self, project_luid_s):
        self.start_log_block()
        project_luids = self.to_list(project_luid_s)
        for project_luid in project_luids:
            url = self.build_api_url(u"projects/{}".format(project_luid))
            self.send_delete_request(url)
        self.end_log_block()

    # Can only delete a site that you have signed into
    def delete_current_site(self):
        self.start_log_block()
        url = self.build_api_url(u"sites/{}".format(self.__site_luid), login=True)
        self.send_delete_request(url)
        self.end_log_block()

    # Can take collection or luid_string
    def delete_workbooks_by_luid(self, wb_luid_s):
        self.start_log_block()
        wb_luids = self.to_list(wb_luid_s)
        for wb_luid in wb_luids:
            # Check if workbook_luid exists
            self.query_workbook_by_luid(wb_luid)
            url = self.build_api_url(u"workbooks/{}".format(wb_luid))
            self.send_delete_request(url)
        self.end_log_block()

    # Can take collection or luid_string
    def delete_workbooks_from_user_favorites_by_luid(self, wb_luid_s, user_luid):
        self.start_log_block()
        wb_luids = self.to_list(wb_luid_s)
        for wb_luid in wb_luids:
            # Check if workbook_luid exists
            self.query_workbook_by_luid(wb_luid)
            url = self.build_api_url(u"favorites/{}/workbooks/{}".format(user_luid, wb_luid))
            self.send_delete_request(url)
        self.end_log_block()

    def delete_views_from_user_favorites_by_luid(self, view_luid_s, user_luid):
        self.start_log_block()
        view_luids = self.to_list(view_luid_s)
        for view_luid in view_luids:
            # Check if workbook_luid exists
            url = self.build_api_url(u"favorites/{}/views/{}".format(user_luid, view_luid))
            self.send_delete_request(url)
        self.end_log_block()

    # Can take collection or string user_luid string
    def remove_users_from_group_by_luid(self, user_luid_s, group_luid):
        self.start_log_block()
        user_luids = self.to_list(user_luid_s)
        for user_luid in user_luids:
            url = self.build_api_url(u"groups/{}/users/{}".format(group_luid, user_luid))
            self.send_delete_request(url)
        self.end_log_block()

    # Can take collection or single user_luid string
    def remove_users_from_site_by_luid(self, user_luid_s):
        self.start_log_block()
        user_luids = self.to_list(user_luid_s)
        for user_luid in user_luids:
            url = self.build_api_url(u"users/{}".format(user_luid))
            self.send_delete_request(url)
        self.end_log_block()

    # You can throw in a cap_dict { capability_name : capability_mode } 'Allow' or 'Deny' but
    # It ignores and atetempts to delete both Allow and Deny and just ignore any error
    # Default is group because you should be doing all your security by groups instead of individuals
    def delete_permissions_by_luids(self, obj_type, obj_luid_s, luid_s, permissions_dict, luid_type='group'):
        self.start_log_block()
        if luid_type not in [u'group', u'user']:
            raise InvalidOptionException(u"luid_type can only be 'group' or 'user'")
        if obj_type not in self.__permissionable_objects:
            raise InvalidOptionException(u'obj_type must be "workbook","datasource" or "project"')

        luids = self.to_list(luid_s)
        obj_luids = self.to_list(obj_luid_s)

        for luid in luids:
            self.log(u'Deleting for LUID {}'.format(luid))
            for obj_luid in obj_luids:
                self.log(u'Deleting for object LUID {}'.format(luid))
                # Check capabiltiies are allowed
                for cap in permissions_dict:
                    if cap not in self.__workbook_caps + self.__datasource_caps + self.__project_caps:
                        raise InvalidOptionException(u"'{}' is not a capability in the REST API".format(cap))
                    if obj_type == u'datasource' and cap not in self.__datasource_caps:
                        self.log(u"'{}' is not a valid capability for a datasource".format(cap))
                    if obj_type == u'workbook' and cap not in self.__workbook_caps:
                        self.log(u"'{}' is not a valid capability for a workbook".format(cap))

                    if permissions_dict.get(cap) == u'Allow':
                        # Delete Allow
                        url = self.build_api_url(u"{}s/{}/permissions/{}s/{}/{}/Allow".format(obj_type, obj_luid,
                                                                                             luid_type, luid, cap))
                        self.send_delete_request(url)
                    elif permissions_dict.get(cap) == u'Deny':
                        # Delete Deny
                        url = self.build_api_url(u"{}s/{}/permissions/{}s/{}/{}/Deny".format(obj_type, obj_luid,
                                                                                            luid_type, luid, cap))
                        self.send_delete_request(url)
                    else:
                        self.log(u'{} set to none, no action'.format(cap))
        self.end_log_block()

    # This completely clears out any permissions that an object has. Use a luid_s_to_delete just some permissions
    def delete_all_permissions_by_luids(self, obj_type, obj_luid_s, luid_s_to_delete=None):
        self.start_log_block()
        if obj_type not in [u'project', u'workbook', u'datasource']:
            raise InvalidOptionException(u"obj_type must be 'project', 'workbook', or 'datasource'")

        self.log(u'Deleting all permissions for {} in following: '.format(obj_type))
        if luid_s_to_delete is not None:
            luids_to_delete = self.to_list(luid_s_to_delete)
            self.log(u'Only deleting permissions for LUIDs {}'.format(luids_to_delete))
        obj_luids = self.to_list(obj_luid_s)
        self.log(unicode(obj_luids))
        for obj_luid in obj_luids:
            if obj_type == 'project':
                obj_permissions = self.query_project_permissions(obj_luid)
            elif obj_type == 'workbook':
                obj_permissions = self.query_workbook_permissions_by_luid(obj_luid)
            elif obj_type == 'datasource':
                obj_permissions = self.query_datasource_permissions(obj_luid)
            try:
                cap_list = self.convert_capabilities_xml_into_obj_list(obj_permissions)
                for gcap_obj in cap_list:
                    gcap_luid = gcap_obj.get_luid()
                    # Don't delete if not in the list to delete
                    if luid_s_to_delete is not None:
                        if gcap_luid not in luids_to_delete:
                            continue
                    gcap_obj_type = gcap_obj.get_obj_type()
                    self.log(u'GranteeCapabilities for {} {}'.format(gcap_obj_type, gcap_luid))
                    capabilities_dict = gcap_obj.get_capabilities_dict()
                    self.delete_permissions_by_luids(obj_type, obj_luids, gcap_luid, capabilities_dict, gcap_obj_type)
            except NoMatchFoundException as e:
                self.log(e)
                self.log(u'{} {} had no permissions assigned, skipping'.format(obj_type, obj_luid))
        self.end_log_block()

    def delete_tags_from_workbook_by_luid(self, wb_luid, tag_s):
        self.start_log_block()
        tags = self.to_list(tag_s)

        deleted_count = 0
        for tag in tags:
            url = self.build_api_url(u"workbooks/{}/tags/{}".format(wb_luid, tag))
            deleted_count += self.send_delete_request(url)
        self.end_log_block()
        return deleted_count

    #
    # End Delete Methods
    #

    #
    # Start Publish methods -- workbook, datasources, file upload
    #

    ''' Publish process can go two way: 
        (1) Initiate File Upload (2) Publish workbook/datasource (less than 64MB) 
        (1) Initiate File Upload (2) Append to File Upload (3) Publish workbook to commit (over 64 MB)
    '''

    def publish_workbook(self, workbook_filename, workbook_name, project_luid, overwrite=False,
                         connection_username=None, connection_password=None, save_credentials=True, show_tabs=True):
        xml = self.publish_content(u'workbook', workbook_filename, workbook_name, project_luid, overwrite,
                                   connection_username, connection_password, save_credentials, show_tabs=show_tabs)
        workbook = xml.xpath(u'//t:workbook', namespaces=self.__ns_map)
        return workbook[0].get('id')

    def publish_datasource(self, ds_filename, ds_name, project_luid, overwrite=False, connection_username=None,
                           connection_password=None, save_credentials=True):
        xml = self.publish_content(u'datasource', ds_filename, ds_name, project_luid, overwrite, connection_username,
                                   connection_password, save_credentials)
        datasource = xml.xpath(u'//t:datasource', namespaces=self.__ns_map)
        return datasource[0].get('id')

    # Main method for publishing a workbook. Should intelligently decide to chunk up if necessary
    # If a TableauDatasource or TableauWorkbook is passed, will upload from its content
    def publish_content(self, content_type, content_filename, content_name, project_luid, overwrite=False,
                        connection_username=None, connection_password=None, save_credentials=True, show_tabs=False,
                        check_published_ds=False):
        # Single upload limit in MB
        single_upload_limit = 20

        # Must be 'workbook' or 'datasource'
        if content_type not in [u'workbook', u'datasource']:
            raise InvalidOptionException(u"content_type must be 'workbook' or 'datasource'")

        file_extension = None
        final_filename = None
        cleanup_temp_file = False
        # If a packaged file object, save the file locally as a temp for upload, then treated as regular file
        if isinstance(content_filename, TableauPackagedFile):
            content_filename = content_filename.save_new_packaged_file(u'temp_packaged_file')
            cleanup_temp_file = True

        # If dealing with either of the objects that represent Tableau content
        if isinstance(content_filename, TableauDatasource):
            file_extension = u'tds'
            # Set file size low so it uses single upload instead of chunked
            file_size_mb = 1
            content_file = StringIO(content_filename.get_datasource_xml())
            final_filename = content_name.replace(" ", "") + "." + file_extension
        elif isinstance(content_filename, TableauWorkbook):
            file_extension = u'twb'
            # Set file size low so it uses single upload instead of chunked
            file_size_mb = 1
            content_file = StringIO(content_filename.get_workbook_xml())
            final_filename = content_name.replace(" ", "") + "." + file_extension

        # When uploading directly from disk
        else:
            for ending in [u'.twb', u'.twbx', u'.tde', u'.tdsx', u'.tds']:
                if content_filename.endswith(ending):
                    file_extension = ending[1:]

                    # Open the file to be uploaded
                    try:
                        content_file = open(content_filename, 'rb')
                        file_size = os.path.getsize(content_filename)
                        file_size_mb = float(file_size) / float(1000000)
                        self.log(u"File {} is size {} MBs".format(content_filename, file_size_mb))
                        final_filename = content_filename
                    except IOError:
                        print u"Error: File '{}' cannot be opened to upload".format(content_filename)
                        raise

            if file_extension is None:
                raise InvalidOptionException(
                    u"File {} does not have an acceptable extension. Should be .twb,.twbx,.tde,.tdsx,.tds".format(
                        content_filename))

        # Request type is mixed and require a boundary
        boundary_string = self.generate_boundary_string()

        # Create the initial XML portion of the request
        publish_request = "--{}\r\n".format(boundary_string)
        publish_request += 'Content-Disposition: name="request_payload"\r\n'
        publish_request += 'Content-Type: text/xml\r\n\r\n'
        publish_request += '<tsRequest>\n<{} name="{}" '.format(content_type, content_name)
        if show_tabs is not False:
            publish_request += 'showTabs="{}"'.format(str(show_tabs).lower())
        publish_request += '>\r\n'
        if connection_username is not None and connection_password is not None:
            publish_request += '<connectionCredentials name="{}" password="{}" embed="{}" />\r\n'.format(
                connection_username, connection_password, str(save_credentials).lower())
        publish_request += '<project id="{}" />\r\n'.format(project_luid)
        publish_request += "</{}></tsRequest>\r\n".format(content_type)
        publish_request += "--{}".format(boundary_string)

        # Upload as single if less than file_size_limit MB
        if file_size_mb <= single_upload_limit:
            # If part of a single upload, this if the next portion
            self.log(u"Less than {} MB, uploading as a single call".format(str(single_upload_limit)))
            publish_request += '\r\n'
            publish_request += 'Content-Disposition: name="tableau_{}"; filename="{}"\r\n'.format(
                content_type, final_filename)
            publish_request += 'Content-Type: application/octet-stream\r\n\r\n'

            # Content needs to be read unencoded from the file
            content = content_file.read()

            # If twb, create a TableauWorkbook object and check for any published data sources
            if file_extension == 'twb' and check_published_ds is True:
                if isinstance(content_filename, TableauWorkbook):
                    wb_obj = content_filename
                else:
                    wb_obj = TableauWorkbook(content)
                for ds in wb_obj.get_datasources().values():
                    if ds.connection.is_published_datasource():
                        pub_ds_name = ds.get_datasource_name()
                        self.log(u"Workbook contains published data source named {}".format(pub_ds_name))
                        try:
                            self.query_datasource_by_name(pub_ds_name)
                        except NoMatchFoundException as e:
                            e_txt = u"Required published data source {} does not exist on this site".format(pub_ds_name)
                            raise NoMatchFoundException(e_txt)
            # Add to string as regular binary, no encoding
            publish_request += content

            publish_request += "\r\n--{}--".format(boundary_string)
            url = self.build_api_url(u"{}s").format(content_type) + "?overwrite={}".format(str(overwrite).lower())
            content_file.close()
            if cleanup_temp_file is True:
                os.remove(final_filename)
            return self.send_publish_request(url, publish_request, boundary_string)
        # Break up into chunks for upload
        else:
            self.log(u"Greater than 10 MB, uploading in chunks")
            upload_session_id = self.initiate_file_upload()

            for piece in self.__read_file_in_chunks(content_file):
                self.log(u"Appending chunk to upload session {}".format(upload_session_id))
                self.append_to_file_upload(upload_session_id, piece, final_filename)

            url = self.build_api_url(u"{}s").format(content_type) + "?uploadSessionId={}".format(
                upload_session_id) + "&{}Type={}".format(content_type, file_extension) + "&overwrite={}".format(
                str(overwrite).lower())
            publish_request += "--"  # Need to finish off the last boundary
            self.log(u"Finishing the upload with a publish request")
            content_file.close()
            if cleanup_temp_file is True:
                os.remove(final_filename)
            return self.send_publish_request(url, publish_request, boundary_string)

    def initiate_file_upload(self):
        url = self.build_api_url(u"fileUploads")
        xml = self.send_post_request(url)
        file_upload = xml.xpath(u'//t:fileUpload', namespaces=self.__ns_map)
        return file_upload[0].get("uploadSessionId")

    # Uploads a check to an already started session
    def append_to_file_upload(self, upload_session_id, content, filename):
        boundary_string = self.generate_boundary_string()
        publish_request = "--{}\r\n".format(boundary_string)
        publish_request += 'Content-Disposition: name="request_payload"\r\n'
        publish_request += 'Content-Type: text/xml\r\n\r\n'
        publish_request += "--{}\r\n".format(boundary_string)
        publish_request += 'Content-Disposition: name="tableau_file"; filename="{}"\r\n'.format(
            filename)
        publish_request += 'Content-Type: application/octet-stream\r\n\r\n'

        publish_request += content

        publish_request += "\r\n--{}--".format(boundary_string)
        url = self.build_api_url(u"fileUploads/{}".format(upload_session_id))
        self.send_append_request(url, publish_request, boundary_string)


# Handles all of the actual HTTP calling
class RestXmlRequest(TableauBase):
    def __init__(self, url, token=None, logger=None):
        self.__defined_response_types = (u'xml', u'png', u'binary')
        self.__defined_http_verbs = (u'post', u'get', u'put', u'delete')
        self.__base_url = url
        self.__xml_request = None
        self.__token = token
        self.__raw_response = None
        self.__last_error = None
        self.__last_url_request = None
        self.__last_response_headers = None
        self.__xml_object = None
        self.__ns_map = {'t': 'http://tableausoftware.com/api'}
        self.logger = logger
        self.__publish = None
        self.__boundary_string = None
        self.__publish_content = None
        self.__http_verb = None
        self.__response_type = None
        self.__last_response_content_type = None
        self.__luid_pattern = r"[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*-[0-9a-fA-F]*"

        try:
            self.set_http_verb('get')
            self.set_response_type('xml')
        except:
            raise

    def set_xml_request(self, xml_request):
        self.__xml_request = xml_request
        return True

    def set_http_verb(self, verb):
        verb = verb.lower()
        if verb in self.__defined_http_verbs:
            self.__http_verb = verb
        else:
            raise InvalidOptionException(u"HTTP Verb '{}' is not defined for this library".format(verb))

    def set_response_type(self, response_type):
        response_type = response_type.lower()
        if response_type in self.__defined_response_types:
            self.__response_type = response_type
        else:
            raise InvalidOptionException(u"Response type '{}' is not defined in this library".format(response_type))

    # Must set a boundary string when publishing
    def set_publish_content(self, content, boundary_string):
        self.__publish = True
        self.__boundary_string = boundary_string
        self.__publish_content = content

    def get_raw_response(self):
        return self.__raw_response

    def get_last_error(self):
        return self.__last_error

    def get_last_url_request(self):
        return self.__last_url_request

    def get_last_response_content_type(self):
        return self.__last_response_content_type

    def get_response(self):
        if self.__response_type == 'xml' and self.__xml_object is not None:
            self.log(u"XML Object Response: {}".format(etree.tostring(self.__xml_object, pretty_print=True, encoding='UTF-8').decode('utf8')))
            return self.__xml_object
        else:
            return self.__raw_response

    # Internal method to handle all of the http request variations, using given library.
    # Using urllib2 with some modification, you could substitute in Requests or httplib
    # depending on preference. Must be able to do the verbs listed in self.defined_http_verbs
    # Larger requests require pagination (starting at 1), thus page_number argument can be called.
    def __make_request(self, page_number=1):
        self.log(u"HTTP verb is {}".format(self.__http_verb))
        url = self.__base_url.encode('utf8')
        if page_number > 0:
            param_separator = '?'
            # If already a parameter, just append
            if '?' in url:
                param_separator = '&'
            url = url + "{}pageNumber={}".format(param_separator, str(page_number))

        self.__last_url_request = url

        # Logic to create correct request
        opener = urllib2.build_opener(urllib2.HTTPHandler)
        request = urllib2.Request(url)
        if self.__http_verb == u'delete':
            request.get_method = lambda: 'DELETE'

        if self.__http_verb == u'put' or self.__http_verb == u'post':
            if self.__publish_content is not None:
                request.add_data(self.__publish_content)
            elif self.__xml_request is not None:
                encoded_request = self.__xml_request.encode('utf8')
                request.add_data(encoded_request)
            else:
                request.add_data("")
        if self.__http_verb == u'put':
            request.get_method = lambda: 'PUT'
        if self.__token is not None:
            request.add_header('X-tableau-auth', self.__token.encode('utf8'))
        if self.__publish is True:
            request.add_header('Content-Type', 'multipart/mixed; boundary={}'.format(self.__boundary_string.encode('utf8')))

        # Need to handle binary return for image somehow
        try:
            self.log(u"Making REST request to Tableau Server using {}".format(self.__http_verb))
            self.log(u"Request URI: {}".format(url))
            if self.__xml_request is not None:
                self.log(u"Request XML:\n{}".format(self.__xml_request))
            response = opener.open(request)

            # Tableau 9.0 doesn't return real UTF-8 but escapes all unicode characters using numeric character encoding
            initial_response = response.read()  # Leave the UTF8 decoding to lxml
            self.__last_response_content_type = response.info().getheader('Content-Type')
            self.log(u"Content type from headers: {}".format(self.__last_response_content_type))
            # Don't botherw with any extra work if the response is expected to be binary
            if self.__response_type == u'binary':
                self.__raw_response = initial_response
                return initial_response

            # Use HTMLParser to get rid of the escaped unicode sequences, then encode the thing as utf-8
            parser = HTMLParser()
            unicode_raw_response = parser.unescape(initial_response)

            try:
                self.__raw_response = unicode_raw_response.encode('utf-8')
            # Sometimes it appears we actually send this stuff in UTF8
            except UnicodeDecodeError:
                self.__raw_response = unicode_raw_response
                unicode_raw_response = unicode_raw_response.decode('utf-8')

            if self.__response_type == 'xml':
                self.log(u"Raw Response:\n{}".format(unicode_raw_response))
            return True
        except urllib2.HTTPError as e:
            # No recoverying from a 500
            if e.code >= 500:
                raise
            # REST API returns 400 type errors that can be recovered from, so handle them
            raw_error_response = e.fp.read()
            self.log(u"Received a {} error, here was response:".format(unicode(e.code)))
            self.log(raw_error_response.decode('utf8'))

            utf8_parser = etree.XMLParser(encoding='utf-8')
            xml = etree.parse(StringIO(raw_error_response), parser=utf8_parser)
            tableau_error = xml.xpath(u'//t:error', namespaces=self.__ns_map)
            error_code = tableau_error[0].get('code')
            tableau_detail = xml.xpath(u'//t:detail', namespaces=self.__ns_map)
            detail_text = tableau_detail[0].text
            detail_luid_match_obj = re.search(self.__luid_pattern, detail_text)
            if detail_luid_match_obj:
                detail_luid = detail_luid_match_obj.group(0)
            else:
                detail_luid = False
            self.log(u'Tableau REST API error code is: {}'.format(error_code))
            # Everything that is not 400 can potentially be recovered from
            if e.code in [401, 402, 403, 404, 405, 409]:
                # If 'not exists' for a delete, recover and log
                if self.__http_verb == 'delete':
                    self.log(u'Delete action attempted on non-exists, keep going')
                if e.code == 409:
                    self.log(u'HTTP 409 error, most likely an already exists')
                raise RecoverableHTTPException(e.code, error_code, detail_luid)
            raise
        except:
            raise

    def request_from_api(self, page_number=1):
        try:
            self.__make_request(page_number)
        except:
            raise
        if self.__response_type == 'xml':
            if self.__raw_response == '':
                return True
            utf8_parser = etree.XMLParser(encoding='utf-8', recover=True)
            xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
            # Set the XML object to the first returned. Will be replaced if there is pagination
            self.__xml_object = xml
            for pagination in xml.xpath(u'//t:pagination', namespaces=self.__ns_map):

                # page_number = int(pagination.get('pageNumber'))
                page_size = int(pagination.get('pageSize'))
                total_available = int(pagination.get('totalAvailable'))
                total_pages = int(math.ceil(float(total_available) / float(page_size)))
                combined_xml_string = u'<tsResponse xmlns="http://tableausoftware.com/api" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://tableausoftware.com/api http://tableausoftware.com/api/ts-api-2.0.xsd">'
                full_xml_obj = None
                for obj in xml.getroot():
                    if obj.tag != 'pagination':
                        full_xml_obj = obj

                # Convert the internal part of the XML response that is not Pagination back into xml text
                # Then convert innermost part into a new XML object
                # This only works in the pre-9.1, non-UTF8 encoded output that includes line breaks
                new_xml_text_lines = etree.tostring(full_xml_obj, encoding='utf8').decode('utf8').split("\n")
                # New style output is not split into multiple lines, add them back in then split
                if len(new_xml_text_lines) == 1:
                    new_xml_text_lines = new_xml_text_lines[0].replace('>', '>\n').split("\n")
                # First and last tags should be removed (spit back with namespace tags that are included via start text
                a = new_xml_text_lines[1:]
                xml_text_lines = a[:-2]

                if total_pages > 1:
                    for i in xrange(2, total_pages + 1):

                        self.__make_request(i)  # Get next page
                        xml = etree.parse(StringIO(self.__raw_response), parser=utf8_parser)
                        for obj in xml.getroot():
                            if obj.tag != 'pagination':
                                full_xml_obj = obj
                        new_xml_text_lines = etree.tostring(full_xml_obj, encoding='utf8').decode('utf8').split("\n")
                        a = new_xml_text_lines[1:]  # Chop first tag
                        xml_text_lines.extend(a[:-2])  # Add the newly brought in lines to the overall text lines

                for line in xml_text_lines:
                    combined_xml_string = combined_xml_string + line
                combined_xml_string += u"</tsResponse>"

                self.__xml_object = etree.parse(StringIO(combined_xml_string.encode('utf8')), parser=utf8_parser)
                return True
        elif self.__response_type in ['binary', 'png']:
            self.log(u'Binary response (binary or png) rather than XML')
            return True


# Represents the GranteeCapabilities from any given. Doesn't implement TableauBase because it's just a complex container
class GranteeCapabilities:
    def __init__(self, obj_type, luid):
        if obj_type not in [u'group', u'user']:
            raise InvalidOptionException(u'GranteeCapabilites type must be "group" or "user"')
        self.obj_type = obj_type
        self.luid = luid
        self.__capabilities = {
            u'AddComment': None,
            u'ChangeHierarchy': None,
            u'ChangePermissions': None,
            u'Connect': None,
            u'Delete': None,
            u'ExportData': None,
            u'ExportImage': None,
            u'ExportXml': None,
            u'Filter': None,
            u'ProjectLeader': None,
            u'Read': None,
            u'ShareView': None,
            u'ViewComments': None,
            u'ViewUnderlyingData': None,
            u'WebAuthoring': None,
            u'Write': None
        }
        self.__allowable_modes = [u'Allow', u'Deny', None]
        self.__server_to_rest_capability_map = {
            u'Add Comment': u'AddComment',
            u'Move': u'ChangeHierarchy',
            u'Set Permissions': u'ChangePermissions',
            u'Connect': u'Connect',
            u'Delete': u'Delete',
            u'View Summary Data': u'ExportData',
            u'Export Image': u'ExportImage',
            u'Download': u'ExportXml',
            u'Download/Save As': u'ExportXml',
            u'Save As': u'ExportXml',
            u'Filter': u'Filter',
            u'Project Leader': u'ProjectLeader',
            u'View': u'Read',
            u'Share Customized': u'ShareView',
            u'View Comments': u'ViewComments',
            u'View Underlying Data': u'ViewUnderlyingData',
            u'Web Edit': u'WebAuthoring',
            u'Save': u'Write'
            }

        self.__role_map = [
            u'Viewer',
            u'Interactor',
            u'Editor',
            u'Data Source Connector',
            u'Data Source Editor',
            u'Publisher',
            u'Project Leader'
        ]

    def set_capability(self, capability_name, mode):
        if mode not in self.__allowable_modes:
            raise InvalidOptionException(u'"{}" is not an allowable mode'.format(mode))
        if capability_name not in self.__capabilities:
            # If it's the Tableau UI naming, translate it over
            if capability_name in self.__server_to_rest_capability_map:
                capability_name = self.__server_to_rest_capability_map[capability_name]
            else:
                raise InvalidOptionException(u'"{}" is not a capability in REST API or Server'.format(capability_name))
        self.__capabilities[capability_name] = mode

    def set_capability_to_unspecified(self, capability_name):
        if capability_name not in self.__capabilities:
            # If it's the Tableau UI naming, translate it over
            if capability_name in self.__server_to_rest_capability_map:
                capability_name = self.__server_to_rest_capability_map[capability_name]
            else:
                raise InvalidOptionException(u'"{}" is not a capability in REST API or Server'.format(capability_name))
        self.__capabilities[capability_name] = None

    def get_capabilities_dict(self):
        return self.__capabilities

    def get_obj_type(self):
        return self.obj_type

    def get_luid(self):
        return self.luid

    def set_obj_type(self, obj_type):
        if obj_type.lower() in [u'group', u'user']:
            self.obj_type = obj_type.lower()
        else:
            raise InvalidOptionException(u'obj_type can only be "group" or "user"')

    def set_luid(self, new_luid):
        self.luid = new_luid

    def set_all_to_deny(self):
        for cap in self.__capabilities:
            self.__capabilities[cap] = u'Deny'

    def set_all_to_allow(self):
        for cap in self.__capabilities:
            self.__capabilities[cap] = u'Allow'

    def set_capabilities_to_match_role(self, role):
        if role not in self.__role_map:
            raise InvalidOptionException(u'{} is not a recognized role'.format(role))
        if role == u'Publisher':
            self.set_all_to_allow()
            self.set_capability(u'Connect', None)
            self.set_capability(u'Download', None)
            self.set_capability(u'Move', None)
            self.set_capability(u'Delete', None)
            self.set_capability(u'Set Permissions', None)
            self.set_capability(u'Project Leader', None)
        elif role == u'Interactor':
            self.set_all_to_allow()
            self.set_capability(u'Connect', None)
            self.set_capability(u'Download', None)
            self.set_capability(u'Move', None)
            self.set_capability(u'Delete', None)
            self.set_capability(u'Set Permissions', None)
            self.set_capability(u'Project Leader', None)
            self.set_capability(u'Save', None)
        elif role == u'Viewer':
            self.set_capability(u'View', u'Allow')
            self.set_capability(u'Export Image', u'Allow')
            self.set_capability(u'View Summary Data', u'Allow')
            self.set_capability(u'View Comments', u'Allow')
            self.set_capability(u'Add Comment', u'Allow')
        elif role == u'Editor':
            self.set_all_to_allow()
            self.set_capability(u'Connect', None)
            self.set_capability(u'Project Leader', None)
        elif role == u'Data Source Connector':
            self.set_capability(u'View', u'Allow')
            self.set_capability(u'Connect', u'Allow')
        elif role == u'Data Source Editor':
            self.set_capability(u'View', u'Allow')
            self.set_capability(u'Connect', u'Allow')
            self.set_capability(u'Save', u'Allow')
            self.set_capability(u'Download', u'Allow')
            self.set_capability(u'Delete', u'Allow')
            self.set_capability(u'Set Permissions', u'Allow')
        elif role == u'Project Leader':
            self.set_capability(u'Project Leader', u'Allow')


# Represents a TWBX or TDSX and allows manipulation of the XML objects inside via their related object
class TableauPackagedFile(TableauBase):
    def __init__(self, zip_file_obj, logger_obj=None):
        self.logger = logger_obj
        self.log(u'TableauPackagedFile initializing')
        self.zf = zipfile.ZipFile(zip_file_obj)
        self.xml_name = None
        self.type = None  # either 'twbx' or 'tdsx'
        self.tableau_object = None
        self.other_files = []
        for name in self.zf.namelist():
            # Ignore anything in the subdirectories
            if name.find('/') == -1:
                if name.endswith('.tds'):
                    self.log(u'Detected a .TDS file in archive, creating a TableauDatasource object')
                    self.type = 'tdsx'
                    self.xml_name = name
                    tds_file_obj = self.zf.open(self.xml_name)
                    self.tableau_object = TableauDatasource(tds_file_obj.read(), self.logger)
                elif name.endswith('.twb'):
                    self.log(u'Detected a .TWB file in archive, creating a TableauDatasource object')
                    self.type = 'twbx'
                    self.xml_name = name
                    twb_file_obj = self.zf.open(self.xml_name)
                    self.tableau_object = TableauWorkbook(twb_file_obj.read(), self.logger)

            else:
                self.other_files.append(name)

    def get_type(self):
        self.start_log_block()
        t = self.type
        self.end_log_block()
        return t

    def get_tableau_object(self):
        self.start_log_block()
        obj = self.tableau_object
        self.end_log_block()
        return obj

    # Appropriate extension added if needed
    def save_new_packaged_file(self, new_filename_no_extension):
        self.start_log_block()
        new_filename = new_filename_no_extension.split('.') # simple algorithm to kill extension

        # Save the object down
        if self.type == 'twbx':
            save_filename = new_filename[0] + '.twbx'
            new_zf = zipfile.ZipFile(save_filename, 'w')
            self.log(u'Creating temporary XML file {}'.format(self.xml_name))
            self.tableau_object.save_workbook_xml(self.xml_name)
            new_zf.write(self.xml_name)
            os.remove(self.xml_name)
        elif self.type == 'tdsx':
            save_filename = new_filename[0] + '.tdsx'
            new_zf = zipfile.ZipFile(save_filename, 'w')
            self.log(u'Creating temporary XML file {}'.format(self.xml_name))
            self.tableau_object.save_datasource_xml(self.xml_name)
            new_zf.write(self.xml_name)
            os.remove(self.xml_name)
            self.log(u'Removed file {}'.format(save_filename))

        temp_directories_to_remove = {}
        for filename in self.other_files:
            self.log(u'Extracting file {} temporarily'.format(filename))
            self.zf.extract(filename)
            new_zf.write(filename)
            os.remove(filename)
            self.log(u'Removed file {}'.format(filename))
            lowest_level = filename.split('/')
            temp_directories_to_remove[lowest_level[0]] = True

        # Cleanup all the temporary directories
        for directory in temp_directories_to_remove:
            shutil.rmtree(directory)
        new_zf.close()
        self.zf.close()

        # Return the filename so it can be opened from disk by other objects
        self.end_log_block()
        return save_filename


# Meant to represent a TDS file, does not handle the file opening
class TableauDatasource(TableauBase):
    def __init__(self, datasource_string, logger_obj=None, translation_on=False):
        self.logger = logger_obj
        self.log(u'Initializing a TableauDatasource object')
        self.ds = StringIO(datasource_string)
        self.start_xml = ""
        self.end_xml = ""
        self.middle_xml = ""
        self.columns_xml = ""
        self.ds_name = None
        self.connection = None
        self.columns_obj = None
        self.translate_flag = False

        # Find connection line and build TableauConnection object
        start_flag = True
        columns_flag = False
        aliases_flag = False
        for line in self.ds:
            # Grab the caption if coming from
            if line.find('<datasource ') != -1:
                # Complete the tag so XML can be parsed
                ds_tag = line + '</datasource>'
                utf8_parser = etree.XMLParser(encoding='utf-8')
                xml = etree.parse(StringIO(ds_tag), parser=utf8_parser)
                xml_obj = xml.getroot()
                if xml_obj.get("caption"):
                    self.ds_name = xml_obj.attrib["caption"]
                elif xml_obj.get("name"):
                    self.ds_name = xml_obj.attrib['name']

                if start_flag is True:
                    self.start_xml += line
                elif start_flag is False:
                    self.end_xml += line
            elif line.find('<connection ') != -1 and start_flag is True:
                self.log(u'Creating a TableauConnection object')
                self.connection = TableauConnection(line)
                self.log(u"This is the connection line:")
                self.log(line)
                start_flag = False
                continue
            else:
                # For columns object creation, the start at the first <column> and end after last </column>
                if line.find(u"<aliases enabled='yes' />") != -1:
                    aliases_flag = True
                    self.middle_xml += line
                    continue
                if aliases_flag is True:
                    if columns_flag is False and line.find('<column') != -1:
                        columns_flag = True
                    # columns can have calculation tags inside that defind a calc
                    if columns_flag is True and line.find('column-instance') != -1:
                        columns_flag = False
                    elif columns_flag is True and line.find('group') != -1:
                        columns_flag = False
                    elif columns_flag is True and line.find('layout') != -1:
                        columns_flag = False
                    if columns_flag is True:
                        self.columns_xml += line
                    elif start_flag is False and columns_flag is False:
                        self.end_xml += line
                elif start_flag is True:
                    self.start_xml += line
                elif start_flag is False and aliases_flag is False:
                    self.middle_xml += line
                elif start_flag is False and aliases_flag is True:
                    self.end_xml += line

        self.log(u'Creating a TableauColumns object')
        self.log(self.columns_xml)
        self.columns_obj = TableauColumns(self.columns_xml, self.logger)

    def get_datasource_name(self):
        self.start_log_block()
        name = self.ds_name
        self.end_log_block()
        return name

    def get_datasource_xml(self):
        self.start_log_block()
        xml = self.start_xml
        # Parameters datasource section does not have a connection tag
        if self.connection is not None:
            xml += self.connection.get_xml_string()
        xml += self.middle_xml
        if self.translate_flag is True:
            xml += self.columns_obj.get_xml_string()
        else:
            xml += self.columns_xml
        xml += self.end_xml
        self.end_log_block()
        return xml

    def save_datasource_xml(self, filename):
        self.start_log_block()
        try:
            lh = open(filename, 'wb')
            lh.write(self.get_datasource_xml())
            lh.close()
            self.end_log_block()
        except IOError:
            self.log(u"Error: File '{}' cannot be opened to write to".format(filename))
            self.end_log_block()
            raise

    def get_columns_obj(self):
        self.start_log_block()
        cols = self.columns_obj
        self.end_log_block()
        return cols

    def translate_columns(self, translation_dict):
        self.start_log_block()
        self.columns_obj.set_translation_dict(translation_dict)
        self.columns_obj.translate_captions()
        self.translate_flag = True
        xml = self.columns_obj.get_xml_string()
        self.end_log_block()
        return xml

class TableauWorkbook(TableauBase):
    def __init__(self, wb_string, logger_obj=None):
        self.logger = logger_obj
        self.log(u'Initialzing a TableauWorkbook object')
        self.wb_string = wb_string
        self.wb = StringIO(self.wb_string)
        self.start_xml = ""
        self.end_xml = ""
        self.datasources = {}
        start_flag = True
        ds_flag = False
        current_ds = ""

        if self.logger is not None:
            self.enable_logging(self.logger)

        for line in self.wb:
            # Start parsing the datasources
            if start_flag is True and ds_flag is False:
                self.start_xml += line
            if start_flag is False and ds_flag is False:
                self.end_xml += line
            if ds_flag is True:
                current_ds += line
                # Break and load the datasource
                if line.find(u"</datasource>") != -1:
                    self.log(u"Building TableauDatasource object")
                    ds_obj = TableauDatasource(current_ds, logger_obj=self.logger)
                    self.datasources[ds_obj.get_datasource_name()] = ds_obj
                    current_ds = ""
            if line.find(u"<datasources") != -1 and start_flag is True:
                start_flag = False
                ds_flag = True

            if line.find(u"</datasources>") != -1 and ds_flag is True:
                self.end_xml += line
                ds_flag = False

    def get_datasources(self):
        self.start_log_block()
        ds = self.datasources
        self.end_log_block()
        return ds

    def get_workbook_xml(self):
        self.start_log_block()
        xml = self.start_xml
        for ds in self.datasources:
            self.log(u'Adding in XML from datasource {}'.format(ds))
            xml += self.datasources.get(ds).get_datasource_xml()
        xml += self.end_xml
        self.end_log_block()
        return xml

    def save_workbook_xml(self, filename):
        self.start_log_block()
        try:
            lh = open(filename, 'wb')
            lh.write(self.get_workbook_xml())
            lh.close()
            self.end_log_block()
        except IOError:
            self.log(u"Error: File '{} cannot be opened to write to".format(filename))
            self.end_log_block()
            raise

# Represents the actual Connection tag of a given datasource
class TableauConnection(TableauBase):
    def __init__(self, connection_line, logger_obj=None):
        self.logger = logger_obj
        # Building from a <connection> tag
        self.xml_obj = None

        if connection_line.find(u"<connection ") != -1:
            self.log(u'Looking at: {}'.format(connection_line))
            # Add ending tag for XML parsing
            connection_line += u"</connection>"
            utf8_parser = etree.XMLParser(encoding='utf-8')
            xml = etree.parse(StringIO(connection_line), parser=utf8_parser)
            self.xml_obj = xml.getroot()
            # xml = etree.fromstring(connection_line)
        else:
            raise InvalidOptionException(u"Must create a TableauConnection from a Connection line")

    def set_dbname(self, new_db_name):
        if self.xml_obj.get("dbname") is not None:
            self.xml_obj.attrib["dbname"] = new_db_name

    def get_dbname(self):
        return self.xml_obj.get("dbname")

    def set_server(self, new_server):
        if self.xml_obj.get("server") is not None:
            self.xml_obj.attrib["server"] = new_server

    def get_server(self):
        return self.xml_obj.get("server")

    def set_username(self, new_username):
        if self.xml_obj.get("username") is not None:
            self.xml_obj.attrib["username"] = new_username

    def set_port(self, new_port):
        if self.xml_obj.get("port") is not None:
            self.xml_obj.attrib["port"] = new_port

    def get_port(self):
        return self.xml_obj.get("port")

    def get_connection_type(self):
        return self.xml_obj.get('class')

    def get_xml_string(self):
        xml_with_ending_tag = etree.tostring(self.xml_obj)
        # Slice off the extra connection ending tag
        return xml_with_ending_tag[0:xml_with_ending_tag.find('</connection>')]

    def is_published_datasource(self):
        if self.xml_obj.get("class") == 'sqlproxy':
            return True
        else:
            return False

    def is_windows_auth(self):
        if self.xml_obj.get("authentication") is not None:
            if self.xml_obj.get("authentication") == 'sspi':
                return True
            else:
                return False

class TableauColumns(TableauBase):
    def __init__(self, column_lines, logger_obj=None):
        self.logger = logger_obj
        self.log(u'Initializing a TableauColumns object')
        self.__translation_dict = None
        # Building from a <column> tag
        self.xml_obj = None
        self.columns_text = "<columns xmlns:user='http://www.tableausoftware.com/xml/user'>\n" + column_lines + "</columns>"
        self.columns_text = self.columns_text.strip()
        self.log(u'Looking at columns:\n {}'.format(self.columns_text))
        utf8_parser = etree.XMLParser(encoding='utf-8')
        xml = etree.parse(StringIO(self.columns_text), parser=utf8_parser)
        self.columns_obj = xml.getroot()
        # xml = etree.fromstring(connection_line)

    def set_translation_dict(self, trans_dict):
        self.start_log_block()
        self.__translation_dict = trans_dict
        self.end_log_block()

    def translate_captions(self):
        self.start_log_block()
        for column in self.get_columns_obj():
            if column.get('caption') is None:
                trans = self.__find_translation(column.get('name'))
            else:
                # Try to match caption first, if not move to name
                trans = self.__find_translation(column.get('caption'))
                if trans is None:
                    trans = self.__find_translation(column.get('name'))
            if trans is not None:
                column.set('caption', trans)
        self.end_log_block()

    def __find_translation(self, match_str):
        self.start_log_block()
        d = self.__translation_dict.get(match_str)
        self.end_log_block()
        return d

    def get_xml_string(self):
        self.start_log_block()
        xml_with_extra_tags = etree.tostring(self.columns_obj, encoding='utf8')
        # Slice off the extra connection ending tag
        first_tag_place = len('<columns xmlns:user="http://www.tableausoftware.com/xml/user">') + 1
        xml = xml_with_extra_tags[first_tag_place:xml_with_extra_tags.find('</columns>')-1]
        self.end_log_block()
        return xml


# Exceptions
class NoMatchFoundException(Exception):
    def __init__(self, msg):
        self.msg = msg


class AlreadyExistsException(Exception):
    def __init__(self, msg, existing_luid):
        self.msg = msg
        self.existing_luid = existing_luid


# Raised when an action is attempted that requires being signed into that site
class NotSignedInException(Exception):
    def __init__(self, msg):
        self.msg = msg


# Raise when something an option is passed that is not valid in the REST API (site_role, permissions name, etc)
class InvalidOptionException(Exception):
    def __init__(self, msg):
        self.msg = msg


class RecoverableHTTPException(Exception):
    def __init__(self, http_code, tableau_error_code, luid):
        self.http_code = http_code
        self.tableau_error_code = tableau_error_code
        self.luid = luid


class MultipleMatchesFoundException(Exception):
    def __init__(self, count):
        self.msg = u'Found {} matches for the request, something has the same name'.format(unicode(count))

