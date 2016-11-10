# tableaujsonservice
repository for tableau json service


This code is based on this great project https://github.com/bryantbhowell/tableau_rest_api. 
The purpose of this project is to allow a generic client to use the python library mentioned above through http calls that returns json. Basically it is a http-json wrapper on python library by Mr Howell, using bottle (https://github.com/bottlepy/bottle) as library to manage http calls. All is packaged and run as a windows service. Main motivation is to be able to use python libraries from a scenario where you can only make rest calls to some service and python is not on your tool stack. This is a scenario that happens when you have to interface an external webapp or portal with tableau server and you can't make python calls from the server running this application, so it is useful to install this service in some server to have a simplified yet powerful version of rest api to call from the "python unfriendly" environment.

To customize service to your own tableau server installation edit the file TableauJsonServiceConfig.py

The to install service run service_install.bat. This will create a windows service called "Tableau Phyton REST API Wrapper Rev.1.00x"
To disinstall the service run service_remove.bat

Once started the service will answer on port 5555.
E.g. browing the url http://localhost:5555/groups   the list of groups in json is returned

The core of the code is in the file TableauJsonService.py that you can easily customize.
For example the following code

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
    
    
represents how the management of call    http://localhost:5555/groups  is managed. 

Licence for this code is LGPL https://www.gnu.org/licenses/lgpl-3.0.en.html

