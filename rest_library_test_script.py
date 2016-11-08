# -*- coding: utf-8 -*-
from tableau_rest_api.tableau_rest_api_unicode import *
import urllib2
import time

# Use your own server credentials
username = u''
password = u''
server = u''
ts1 = TableauRestApi(server, username, password, u'default')
logger = Logger(u'sample_rest_script.log')

ts1.enable_logging(logger)

ts1.signin()

new_site_name = u'Test Site - ようこそ'
new_site_content_url = u'ts'
try:
    # Determine if site exists with current name. Delete if it does.
    # Then create new site with the same name and contentUrl
    try:
        delete_login_content_url = ts1.query_site_content_url_by_site_name(u'Test Site - приветствие')
        print 'Received content_url to delete ' + delete_login_content_url
        site_to_delete = TableauRestApi(server, username, password, delete_login_content_url)
        site_to_delete.enable_logging(logger)
        site_to_delete.signin()
        print 'Signed in successfully to ' + delete_login_content_url

        print 'Querying the current site'
        site_xml = site_to_delete.query_current_site()
        print site_xml

        print 'Attempting to delete current site'
        site_to_delete.delete_current_site()
        print "Deleted site " + new_site_name.encode('utf8')
    except NoMatchFoundException as e:
        print e.msg.encode('utf8')
        print "Cannot delete site that does not exist"
    except Exception as e:
        raise

    try:
        # Create the new site
        print 'Now going into the create site'
        # You can log anything extra you need to, although the default logging is very verbose
        ts1.log('Logging with the log function')
        new_site_id = ts1.create_site(new_site_name, new_site_content_url)
        print 'Created new site ' + new_site_id
    except AlreadyExistsException as e:
        print e.msg
        print "Cannot create new site, exiting"
        exit()
    except Exception as e:
        raise

    # Once we've created the site, we need to sign into it to do anything else
    new_site = TableauRestApi(server, username, password, new_site_content_url)
    new_site.enable_logging(logger)
    try:
        new_site.signin()
        # Add groups and users to the site
        print 'Signed in successfully to ' + new_site_content_url

        # Update the site name
        print 'Updating site name'
        new_site.update_current_site(u'Test Site - приветствие')

        projects_to_create = [u'Sandbox',
                              u'Approved Datasources',
                              u'Production',
                              u'工程']
        for project in projects_to_create:
            msg = u"Creating Project '{}'".format(project)
            print msg.encode('utf8')
            new_proj_luid = new_site.create_project(project)
        
        groups_to_create = [
            u'Publishers',
            u'Site Admins',
            u'Super Admins',
            u'Sales',
            u'Marketing',
            u'IT',
            u'VPs',
            u'优胜者',
            u'فاتح']
        for group in groups_to_create:
            msg = u"Creating Group '{}'".format(group)
            print msg.encode('utf8')
            new_group_luid = new_site.create_group(group)
            time.sleep(1)
            print "updating the group name"
            new_site.update_group_by_luid(new_group_luid, group + u' (Awesome)')

        print "Sleeping 1 second for group creation to finish"
        # It does take a second for the indexing to update, so if you've made a lot of changes, pause for 1 sec
        time.sleep(1)

        print "Get all the groups"
        groups_on_site = new_site.query_groups()

        # Assign permissions on each project, for each group

        print "Converting the groups to a dict"
        # Convert the list to a dict {name : luid}
        groups_dict = new_site.convert_xml_list_to_name_id_dict(groups_on_site)
        print groups_dict

        sandbox_luid = new_site.query_project_luid_by_name(u'工程')

        # Change the Sandbox name
        new_site.update_project_by_name(u'工程', u'Protected Sandbox', u'This is only for important people')

        group_luids = groups_dict.values()
        gcap_obj_list = []
        for group_luid in group_luids:
            gcap = GranteeCapabilities(u'group', group_luid)
            gcap.set_capability(u'Read', u'Allow')
            gcap.set_capability(u'Filter', u'Allow')
            gcap.set_capability(u'ShareView', u'Allow')
            gcap.set_capability(u'Delete', u'Allow')
            gcap.set_capability(u'Write', u'Deny')
            gcap.set_capability(u'View Underlying Data', u'Deny')
            gcap_obj_list.append(gcap)

        print 'Adding permissions to Sandbox'
        new_site.update_permissions_by_gcap_obj_list(u'project', sandbox_luid, gcap_obj_list)

        print 'Updating the permissions on the Sandbox'
        new_site.update_permissions_by_gcap_obj_list(u'project', sandbox_luid, gcap_obj_list)

        # Create some fake users to assign to groups
        new_user_luids = []
        new_usernames = {
            u"андрей.соколов": u"андрей соколов",
            u"հայկ.խաչատրյան": u"հայկ խաչատրյան",
            u"পাওলা.গাজী": u"পাওলা গাজী",
            u"서연.주": u"서연 주",
            u"jesús.franco": u"Jesús Franco",
            u"susan.jackson": u"Susan Jackson"
        }
        for username in new_usernames:
            full_name = new_usernames[username]
            print "Creating User '{}' named '{}'".format(username.encode('utf8'), full_name.encode('utf8'))
            new_user_luid = new_site.add_user(username, full_name, u'Interactor', u'password', u'nobody@nowhere.com')
            print "New User LUID : {}".format(new_user_luid)
            new_user_luids.append(new_user_luid)
        
        for group in groups_dict:
            print "Adding users to group {}".format(group.encode('utf8'))
            new_site.add_users_to_group_by_luid(new_user_luids, groups_dict.get(group))

        example_username = u'հայկ.խաչատրյան'

        user_1_luid = new_site.query_user_luid_by_username(example_username)
        print " A user's luid: {}".format(user_1_luid)
        # Teardown users
        # Delete all of the users that were just created
        # new_site.remove_users_from_site_by_luid(new_user_luids)

        try:
            project_luid = new_site.query_project_luid_by_name(u'Protected Sandbox')
            print "Sandbox project luid: " + project_luid

            print "Querying project permissions"
            project_permissions = new_site.query_project_permissions_by_luid(project_luid)
            # print project_permissions

            # Publish a datasource to the Sandbox project
            print 'Publishing datasource to Protected Sandbox'
            tde_filename = '.tde'
            tde_content_name = ''
            new_ds_luid = new_site.publish_datasource(tde_filename, tde_content_name, project_luid, True)
            print 'Publishing as {}'.format(new_ds_luid)
            print "Query the datasource"
            ds_xml = new_site.query_datasource_by_luid(new_ds_luid)

            print "Querying datasource permissions"
            ds_perms = new_site.query_datasource_permissions_by_luid(new_ds_luid)
            print ds_perms

            print "Querying All datasources"
            datasources = new_site.query_datasources()

            print 'Publishing TWBX workbook to PRoduction'
            production_luid = new_site.query_project_luid_by_name(u'Production')
            twbx_filename = '.twbx'  # Replace with your own test file
            twbx_content_name = ''  # Replace with your own name
            new_wb_luid = new_site.publish_workbook(twbx_filename, twbx_content_name, production_luid, True)
            print 'Moving workbook to Sandbox'
            new_site.update_workbook_by_luid(new_wb_luid, sandbox_luid, show_tabs=True)
            print "querying workbook"
            wb_xml = new_site.query_workbook_by_luid(new_wb_luid)

            print "assign permissions to workbook"
            new_site.add_permissions_by_gcap_obj_list(u'workbook', new_wb_luid, gcap_obj_list)

            print "Assigning permission to datasource"
            try:
                new_site.add_permissions_by_gcap_obj_list(u'datasource', new_ds_luid, gcap_obj_list)
            except InvalidOptionException as e:
                print e.msg
            # print "Deleting the published DS"
            # new_site.delete_datasources_by_luid(new_ds_luid)

            print "Moving datasource to production"
            new_site.update_datasource_by_luid(new_ds_luid, u'Moved Datasource', production_luid)

            print "Query workbook connections"
            wb_connections = new_site.query_workbook_connections_by_luid(new_wb_luid)
            print wb_connections

            print "Querying workbook permissions"
            wb_permissions = new_site.query_workbook_permissions_by_luid(new_wb_luid)
            print wb_permissions

            # print "Adding permissions to workbook"
            # new_site.add_permissions_by_luids('workbook', new_wb_luid, group_luids, sandbox_permissions, 'group')

            # print "Deleting Permissions from workbook"
            # new_site.delete_permissions_by_luids('workbook', new_wb_luid, group_luids, sandbox_permissions, 'group')

            # print "Deleting Permissions from project"
            # new_site.delete_permissions_by_luids('project', project_luid, group_luids, sandbox_permissions, 'group')

            print "Querying workbook views"
            wb_views = new_site.query_workbook_views_by_luid(new_wb_luid, True)
            print wb_views

            wb_views_dict = new_site.convert_xml_list_to_name_id_dict(wb_views)

            print wb_views_dict

            for wb_view in wb_views_dict:
                print "Adding {} to favorites for User 1".format(wb_view)
                new_site.add_view_to_user_favorites_by_luid('Fav: {}'.format(wb_view), wb_views_dict.get(wb_view), new_site.query_user_luid_by_username(example_username))

            for wb_view in wb_views_dict:
                print "Deleting {} to favorites for User 1".format(wb_view)
                new_site.delete_views_from_user_favorites_by_luid(wb_views_dict.get(wb_view), new_site.query_user_luid_by_username(example_username))

            # Save workbook preview image
            print "Saving workbook preview image"
            new_site.save_workbook_preview_image_by_luid(new_wb_luid, 'Workbook preview')

            # Saving view as file
            for wb_view in wb_views_dict:
                print "Saving a png for {}".format(wb_view)
                new_site.save_workbook_view_preview_image_by_luid(new_wb_luid, wb_views_dict.get(wb_view), '{}_preview'.format(wb_view))

            print "Saving workbook file"
            new_site.download_workbook_by_luid(new_wb_luid, u'saved workbook', no_obj_return=True)

            print "Saving Datasource"
            new_site.download_datasource_by_luid(new_ds_luid, u'saved_datasource')
            print 'Adding tags to workbook'
            new_site.add_tags_to_workbook_by_luid(new_wb_luid, [u'workbooks', u'flights', u'cool'])

            print 'Deleting a tag from workbook'
            new_site.delete_tags_from_workbook_by_luid(new_wb_luid, 'flights')

            print "Add workbook to favorites for bhowell"
            new_site.add_workbook_to_user_favorites_by_luid(u'My favorite workbook', new_wb_luid, new_site.query_user_luid_by_username(example_username))

            print "Deleting workbook from favorites for bhowell"
            new_site.delete_workbooks_from_user_favorites_by_luid(new_wb_luid, new_site.query_user_luid_by_username(example_username))

            # All of these below are just tests of the different files you can upload
            print "Publishing a TWB"
            twb_luid = new_site.publish_workbook('.twb', u'TWB Publish Test', project_luid)

            print "Downloading TWB"
            new_site.download_workbook_by_luid(twb_luid, u'TWB Save')

            print "Publishing a TDS"
            tds_luid = new_site.publish_datasource('.tds', u'SS TDS', project_luid)

            print "Publishing TDS with credentials -- reordered args"
            tds_cred_luid = new_site.publish_datasource('.tds', u'TDS w Creds', project_luid, connection_username='', overwrite=True, connection_password='')

            # print "Update Datasource connection"
            # new_site.update_datasource_connection_by_luid(tds_cred_luid, 'localhost', '5432', db_username, db_password)

            print "Saving TDS"
            new_site.download_datasource_by_luid(tds_luid, u'TDS Save')

            print "Publishing a TDSX"
            new_site.publish_datasource('.tdsx', u'TDSX Publish Test', project_luid)

        except NoMatchFoundException as e:
                print e.msg.encode('utf8')
        except:
            raise

    except NoMatchFoundException as e:
        print e.msg.encode('utf8')
    except:
        raise
    
except urllib2.HTTPError as e:
    print e.code
    print e.msg
    print e.hdrs
    print e.fp
except Exception as e:
   raise
