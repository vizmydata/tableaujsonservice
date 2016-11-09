# ====================================================================

# Tableau REST API wrapper Configuration
#
#                (C) 2015 Deimos Engineering s.r.l.
#                       Build 018_2015-11-02

# ====================================================================

#
# Server connection data
# write your server url and tableau site
__server__ = 'http://localhost'
__site__ = 'default'

# write username and password of a tableau user enabled to use rest api
__username__ = 'admin'
__password__ = 'adminpwd'

#
# Cache file settings. use a path on your file system
#
__cachedir__ = 'C:\\SIMS2\\TableauPhytonWrapper\\Cache\\'

#
# Log file settings and error log file settings. use path on your file system
#
__loggerfile__ = 'C:\\SIMS2\\TableauPhytonWrapper\\Log\\rest_wrapper.log'
__errorlogfile__= 'C:\\SIMS2\\TableauPhytonWrapper\\Log\\errors.log'
# __loggerfile = None

class TableauJsonServiceConfig:

    def __init__(self):

        self.server = __server__
        self.site = __site__

        self.username = __username__
        self.password = __password__

        self.cachedir = __cachedir__

        self.loggerfile = __loggerfile__
        self.errorlogfile = __errorlogfile__

    def getServer(self) :
        return self.server

    def getSite(self) :
        return self.site

    def getUsername(self) :
        return self.username

    def getPassword(self) :
        return self.password

    def getCacheDir(self) :
        return self.cachedir

    def getLoggerFile(self) :
        return self.loggerfile
    def getErrorLogFile(self):
        return  self.errorlogfile
