# ====================================================================

# Tableau REST API wrapper to tableau_rest_api.py (Tested on 1.5.2)
#
#                (C) 2015 Deimos Engineering s.r.l.
#                       Build 020_2015-12-11

# ====================================================================

from bottle import Bottle, request, response, route, run, template, abort, error
from datetime import datetime
from functools import wraps
import logging
from tableau_rest_api import *
from TableauJsonServiceConfig import * 
import urllib2
import time

# ====================================================================

__serverconfig = TableauJsonServiceConfig()

__server = __serverconfig.getServer()
__site = __serverconfig.getSite()

__username = __serverconfig.getUsername()
__password = __serverconfig.getPassword()

__cachedir = __serverconfig.getCacheDir()

__loggerfile = __serverconfig.getLoggerFile()
__errorlogfile = __serverconfig.getErrorLogFile();
# =============================logger==================================
logger = logging.getLogger('myapp')

# set up the logger
logger.setLevel(logging.INFO)
file_handler = logging.FileHandler(__errorlogfile)
formatter = logging.Formatter('%(msg)s')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_to_logger(fn):
    '''
    Wrap a Bottle request so that a log line is emitted after it's handled.
    (This decorator can be extended to take the desired logger as a param.)
    '''
    @wraps(fn)
    def _log_to_logger(*args, **kwargs):
        request_time = datetime.now()
        try:
            actual_response = fn(*args, **kwargs)
            # modify this to log exactly what you need:
            logger.info('%s %s %s %s %s' % (request.remote_addr,
                                            request_time,
                                            request.method,
                                            request.url,
                                            response.status))
            return actual_response
        except Exception , eccez:
            logger.info('%s %s %s %s %s' % (request.remote_addr,
                                            request_time,
                                            request.method,
                                            request.url,
                                            str(eccez)))
            raise

    return _log_to_logger

# ====================================================================

#
# The one and only wrapper application
#
wrapper = Bottle()
wrapper.install(log_to_logger)
# ====================================================================

#
# Root and default handlers
#
@wrapper.route('/')
def root():

    abort(401, "Sito per solo uso interno !")

@wrapper.error(404)
def error404(error):

    return "Funzione non disponibile !"

@wrapper.route('/ver')
def ver():

    return "Tableau REST API wrapper<br><br>Versione : 0.15-1.5.2<br>Aggiornamento : 2015-10-19"

# ====================================================================

#
# Handlers
#
@wrapper.route('/groups')
def groups():

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_groups()
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('groups')

    return tab_data_json

@wrapper.route('/users')
def users():

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_users()
    tab_usrs = TableauWrapperUsers(tab_data)
    tab_data_json = tab_usrs.get_users_json()

    return tab_data_json

@wrapper.route('/usersbygroup/<groupname_or_luid>')
def usersbygroup(groupname_or_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    if tab_srv.is_luid(groupname_or_luid):
        group_luid = groupname_or_luid
    else:
        group_luid = tab_srv.query_group_luid_by_name(groupname_or_luid)

    tab_data = tab_srv.query_users_in_group_by_luid(group_luid)
    tab_usrs = TableauWrapperUsers(tab_data)
    tab_data_json = tab_usrs.get_users_json()

    return tab_data_json

@wrapper.route('/sites')
def sites():

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_sites()
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('sites')

    return tab_data_json

@wrapper.route('/projects')
def projects():

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_projects()
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('projects')

    return tab_data_json

@wrapper.route('/datasources')
def datasources():

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_datasources()
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('datasources')

    return tab_data_json

@wrapper.route('/workbooks')
def workbooks():

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_workbooks()
    tab_objs = TableauWrapperWorkbooks(tab_data)
    tab_data_json = tab_objs.get_objects_json()

    return tab_data_json

@wrapper.route('/workbooksbyuser/<username_or_luid>')
def workbooksbyuser(username_or_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    if tab_srv.is_luid(username_or_luid):
        user_luid = username_or_luid
    else:
        user_luid = tab_srv.query_user_luid_by_username(username_or_luid)

    tab_data = tab_srv.query_workbooks_for_user_by_luid(user_luid)
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('workbooks')

    return tab_data_json

@wrapper.route('/workbooksbyproject/<projectname_or_luid>')
def workbooksbyproject(projectname_or_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_workbooks_in_project(projectname_or_luid)
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('workbooks')

    return tab_data_json

@wrapper.route('/viewsbyworkbook/<workbookname_or_luid>')
def viewsbyworkbook(workbookname_or_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    if tab_srv.is_luid(workbookname_or_luid):
        tab_data = tab_srv.query_workbook_views_by_luid(workbookname_or_luid)
    else:
        tab_data = tab_srv.query_workbook_views_by_workbook_name(workbookname_or_luid)

    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('views')

    return tab_data_json

@wrapper.route('/viewgetpreview/<workbook_luid>/<view_luid>')
def viewgetpreview(workbook_luid=None, view_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    filename = __cachedir + view_luid;
    tab_srv.save_workbook_view_preview_image_by_luid(workbook_luid, view_luid, filename);
    filename = filename.replace("\\", "\\\\");
    filename = filename + '.png';

    cap_object_type_name = 'previews';
    objectnum = 0

    caps_data_json = '{ "' + cap_object_type_name + '": ['

    capInfo = '{'
    capInfo += ' "wluid": "'
    capInfo += workbook_luid
    capInfo += '", '
    capInfo += ' "vluid": "'
    capInfo += view_luid
    capInfo += '", '
    capInfo += ' "filename": "'
    capInfo += filename + '"'
    capInfo += ' }'

    if objectnum > 0:
        caps_data_json += ', '
    caps_data_json += capInfo

    caps_data_json += ' ] }'

    return caps_data_json

@wrapper.route('/permissionforworkbook/<workbook_luid>')
def permissionforworkbook(workbook_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    tab_data = tab_srv.query_workbook_permissions_by_luid(workbook_luid)
    cap_list = tab_srv.convert_capabilities_xml_into_obj_list(tab_data)

    cap_object_type_name = 'capabilities';
    per_object_type_name = 'permissions';

    objectnum = 0
    caps_data_json = '{ "' + cap_object_type_name + '": ['

    for gcap_obj in cap_list:
        gcap_obj_type = gcap_obj.get_obj_type()
        gcap_luid = gcap_obj.get_luid()
        capabilities_dict = gcap_obj.get_capabilities_dict()

        permnum = 0
        permissions = '"' + per_object_type_name + '": [';

        for cap in capabilities_dict:
            permission = TableauPermission(cap, capabilities_dict[cap]);
            if permnum > 0:
                permissions += ', '
            permissions += permission.tostring()
            permnum = permnum + 1
        permissions += ' ]'

        capInfo = '{'
        capInfo += ' "type": "'
        capInfo += gcap_obj_type
        capInfo += '", '
        capInfo += ' "luid": "'
        capInfo += gcap_luid
        capInfo += '", '
        capInfo += permissions
        capInfo += ' }'

        if objectnum > 0:
            caps_data_json += ', '
        caps_data_json += capInfo
        objectnum = objectnum + 1

    caps_data_json += ' ] }'

    return caps_data_json

@wrapper.route('/userworkbookdeny/<user_luid>/<workbook_luid>')
def userworkbookdeny(user_luid=None, workbook_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    ucap_obj_list = []
    ucap = GranteeCapabilities('user', user_luid)
    ucap.set_capability('AddComment', 'Deny')
    ucap.set_capability('ChangeHierarchy', 'Deny')
    ucap.set_capability('ChangePermissions', 'Deny')
    ucap.set_capability('Delete', 'Deny')
    ucap.set_capability('ExportData', 'Deny')
    ucap.set_capability('ExportImage', 'Deny')
    ucap.set_capability('ExportXml', 'Deny')
    ucap.set_capability('Filter', 'Deny')
    ucap.set_capability('Read', 'Deny')
    ucap.set_capability('ShareView', 'Deny')
    ucap.set_capability('ViewComments', 'Deny')
    ucap.set_capability('ViewUnderlyingData', 'Deny')
    ucap.set_capability('WebAuthoring', 'Deny')
    ucap.set_capability('Write', 'Deny')
    ucap_obj_list.append(ucap)

    tab_srv.update_permissions_by_gcap_obj_list('workbook', workbook_luid, ucap_obj_list)

    return "successed"

@wrapper.route('/userworkbookdefault/<user_luid>/<workbook_luid>')
def userworkbookdefault(user_luid=None, workbook_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    tab_srv.delete_all_permissions_by_luids('workbook', workbook_luid, user_luid)

    return "successed"

@wrapper.route('/useradd/<username>/<user_password>/<userrole>/<user_fullname>/<user_mail>/<update_if_exist>')
def useradd(username=None, user_password=None, userrole=None, user_fullname=None,user_mail=None,update_if_exist=False):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    if user_fullname is None or len(user_fullname) < 1:
        user_fullname = username

    #def add_user(self, username, fullname, site_role=u'Unlicensed', password=None, email=None, update_if_exists=False):
    new_user_luid = tab_srv.add_user(username, user_fullname, userrole, user_password, user_mail,update_if_exist=='True')

    usrs = []
    usr = TableauWrapperUser(new_user_luid, username, userrole)
    usrs.append(usr);

    tab_usrs = TableauWrapperUsers(None)
    tab_usrs.set_users(usrs);
    tab_data_json = tab_usrs.get_users_json()

    return tab_data_json

@wrapper.route('/useraddad/<username>/<userrole>')
def useraddad(username=None, userrole=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    user_fullname = username
    new_user_luid = tab_srv.add_user(username, user_fullname, userrole, None, None)

    usrs = []
    usr = TableauWrapperUser(new_user_luid, username, userrole)
    usrs.append(usr);

    tab_usrs = TableauWrapperUsers(None)
    tab_usrs.set_users(usrs);
    tab_data_json = tab_usrs.get_users_json()

    return tab_data_json

@wrapper.route('/userremove/<user_luid>')
def userremove(user_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    tab_srv.remove_users_from_site_by_luid(user_luid)

    return "successed"

@wrapper.route('/useraddtogroup/<user_luid>/<group_luid>')
def useraddtogroup(user_luid=None, group_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    tab_srv.add_users_to_group_by_luid(user_luid, group_luid)

    return "successed"

@wrapper.route('/userremovefromgroup/<user_luid>/<group_luid>')
def userremovefromgroup(user_luid=None, group_luid=None):

    tab_srv = TableauRestApi(__server, __username, __password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()

    tab_srv.remove_users_from_group_by_luid(user_luid, group_luid)

    return "successed"

@wrapper.route('/userchecksignin/<user_name>/<password>')
def userchecksignin(user_name=None, password=None):

    tab_srv = TableauRestApi(__server, user_name, password, __site)
    if __loggerfile is not None :
        logger = Logger(__loggerfile)
        tab_srv.enable_logging(logger)

    tab_srv.signin()
    tab_data = tab_srv.query_workbooks()
    tab_objs = TableauWrapperObjects(tab_data)
    tab_data_json = tab_objs.get_objects_json('workbooks')

    return tab_data_json

# ====================================================================

class TableauWrapperWorkbook:
    def __init__(self,id,name,contentUrl,projectid,projectname):
        self.id = id
        self.name =name
        self.contentUrl = contentUrl
        self.projectid = projectid
        self.projectname=projectname

    def tostring(self):
        objinfo = '{'

        objinfo += ' "luid": "'
        objinfo += self.id
        objinfo += '", '
        objinfo += ' "name": "'
        objinfo += self.name
        objinfo += '",'
        objinfo += ' "contentUrl": "'
        objinfo += self.contentUrl
        objinfo += '",'
        objinfo += ' "projectluid": "'
        objinfo += self.projectid
        objinfo += '",'
        objinfo += ' "projectname": "'
        objinfo += self.projectname
        objinfo += '"'

        objinfo += ' }'

        return objinfo

class TableauWrapperWorkbooks:

    def __init__(self,lxml_obj):
        d = []
        for element in lxml_obj:
            e_id = element.get("id")
            e_name = element.get("name")
            e_contentUrl = element.get("contentUrl")
            for subEl in element:
                if subEl.tag.endswith("project"):
                    e_projectid=subEl.get("id")
                    e_projectname = subEl.get("name")


            w = TableauWrapperWorkbook(e_id,e_name,e_contentUrl,e_projectid,e_projectname)
            d.append(w)

        self.__collection = d

    def get_objects_json(self):

            objectnum = 0
            result = '{ "workbooks": ['

            for w in self.__collection:
                winfo = w.tostring()
                if objectnum > 0:
                    result += ', '
                result += winfo
                objectnum = objectnum + 1

            result = result + ' ] }'

            return result;


class TableauWrapperObject:

    def __init__(self, id, name):

        self.id = id
        self.name = name

    def tostring(self):

        objinfo = '{'

        objinfo += ' "luid": "'
        objinfo += self.id
        objinfo += '", '
        objinfo += ' "name": "'
        objinfo += self.name
        objinfo += '"'

        objinfo += ' }'

        return objinfo

class TableauWrapperObjects:

    def __init__(self, lxml_obj):

        d = []
        for element in lxml_obj:
            e_id = element.get("id")
            # If list is collection, have to run one deeper
            if e_id is None:
                for list_element in element:
                    tab_usr = TableauWrapperObject(list_element.get("id"),list_element.get("name"))
                    d.append(tab_usr);
            else:
                tab_usr = TableauWrapperObject(e_id,element.get("name"))
                d.append(tab_usr);

        self.__users = d

    def get_objects_json(self, object_type_name):

        objectnum = 0
        result = '{ "' + object_type_name + '": ['

        for user in self.__users:
            userinfo = user.tostring()
            if objectnum > 0:
                result += ', '
            result += userinfo
            objectnum = objectnum + 1

        result = result + ' ] }'

        return result;

# ====================================================================

class TableauWrapperUser:

    def __init__(self, id, name, siterole):

        self.id = id
        self.name = name
        self.siterole = siterole

    def tostring(self):

        userinfo = '{'

        userinfo += ' "userluid": "'
        userinfo += self.id
        userinfo += '", '
        userinfo += ' "name": "'
        userinfo += self.name
        userinfo += '", '
        userinfo += ' "role": "'
        userinfo += self.siterole
        userinfo += '"'

        userinfo += ' }'

        return userinfo

# ====================================================================



class TableauWrapperUsers:

    def __init__(self, lxml_obj):

        d = []
        if lxml_obj is not None :
            for element in lxml_obj:
                e_id = element.get("id")
                # If list is collection, have to run one deeper
                if e_id is None:
                    for list_element in element:
                        tab_usr = TableauWrapperUser(list_element.get("id"),list_element.get("name"), list_element.get("siteRole"))
                        d.append(tab_usr);
                else:
                    tab_usr = TableauWrapperUser(e_id,element.get("name"), element.get("siteRole"))
                    d.append(tab_usr);

        self.__users = d

    def set_users(self, users):
        self.__users = users

    def get_users_json(self):

        result = '{ "users": ['
        usernum = 0
        for user in self.__users:
            userinfo = user.tostring()
            if usernum > 0:
                result += ', '
            result += userinfo
            usernum = usernum + 1

        result = result + ' ] }'

        return result;

# ====================================================================

class TableauPermission:

    def __init__(self, name, mode):

        self.__name = name
        self.__mode = mode

    def tostring(self):

        mode = self.__mode;
        if mode is None :
            mode = "None" 

        objinfo = '{'

        objinfo += ' "name": "'
        objinfo += self.__name
        objinfo += '", '
        objinfo += ' "mode": "'
        objinfo += mode
        objinfo += '"'

        objinfo += ' }'

        return objinfo

# ====================================================================

#
# Starts the wrapper - Skipped for "asservice" mode.
# remember to comment following line to run as a service
wrapper.run(host='localhost', port=5555, debug=True)

# ====================================================================
