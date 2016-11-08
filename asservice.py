# ====================================================================

# Tableau REST API wrapper to tableau_rest_api.py (Tested against 1.5.2)
#
#                (C) 2015 Deimos Engineering s.r.l.

# ====================================================================

###
### As service Phyton script
###     Original author "pacopablo"
###     Adapted by "rvattolo"
###
### Usage : python aservice.py install (or / then start, stop, remove)
###

# ====================================================================

import sys
import os
import select
import traceback
import win32serviceutil
import win32service
import win32event
from threading import Thread, Event

import servicemanager
from wsgiref.simple_server import make_server, WSGIRequestHandler

from bottle import ServerAdapter, run as bottle_run

__virtualenv_directory__ = None

if __virtualenv_directory__:
    activationscript = os.path.join(__virtualenv_directory__, 'Scripts', 'activate_this.py')
    execfile(activationscript, {'__file__': activationscript})

# ====================================================================

#
# Service descriptions and hardcoded binding info
#

__service_name__ = 'Tableau Phyton REST API Wrapper'
__service_display_name__ = 'Tableau Phyton REST API Wrapper Rev. 1.00x'
__service_description__ = 'Wraps Tableau REST API requests'

#

__host__ = 'localhost'
__port__ = '5555'

# ====================================================================

#
# Imports the wrapper application
#

from TableauJsonService import wrapper
__bottle_app__ = wrapper

# ====================================================================

def getTrace():
    msg = traceback.format_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
    msg = ''.join(msg)
    msg = msg.split('\012')
    msg = ''.join(msg)
    msg += '\n'
    return msg

class WSGIRefHandleOneServer(ServerAdapter):

    def run(self, handler): # pragma: no cover

        handler_class = WSGIRequestHandler
        if self.quiet:
            class QuietHandler(WSGIRequestHandler):
                def log_request(*args, **kw): pass
            handler_class = QuietHandler
        srv = make_server(self.host, self.port, handler, handler_class=handler_class)
        servicemanager.LogInfoMsg("Bound to %s:%s" % (__host__ or '0.0.0.0', __port__))
        srv_wait = srv.fileno()

        # The default  .serve_forever() call blocks waiting for requests.
        # This causes the side effect of only shutting down the service if a
        # request is handled.
        #
        # To fix this, we use the one-request-at-a-time ".handle_request"
        # method.  Instead of sitting polling, we use select to sleep for a
        # second and still be able to handle the request.
        while self.options['notifyEvent'].isSet():
            ready = select.select([srv_wait], [], [], 1)
            if srv_wait in ready[0]:
                srv.handle_request()
            continue

class BottleWsgiServer(Thread):

    def __init__(self, eventNotifyObj):
        Thread.__init__(self)
        self.notifyEvent = eventNotifyObj

    def run ( self ):
        bottle_run(__bottle_app__, host = __host__, port = __port__, server = WSGIRefHandleOneServer, 
                                                reloader = False, quiet = True, notifyEvent = self.notifyEvent)

class BottleService(win32serviceutil.ServiceFramework):

    _svc_name_ = __service_name__
    _svc_display_name_ = __service_display_name__
    _svc_description_ = __service_description__

    def __init__(self, args):

        win32serviceutil.ServiceFramework.__init__(self, args)
        self.redirectOutput()
        # Create an event which we will use to wait on.
        # The "service stop" request will set this event.
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def redirectOutput(self):

        sys.stdout.close()
        sys.stderr.close()

        sys.stdout = NullOutput()
        sys.stderr = NullOutput()

    def SvcStop(self):

        # Before we do anything, tell the SCM we are starting the stop process.
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # stop the process if necessary
        self.thread_event.clear()
        self.bottle_srv.join()

        # And set my event.
        win32event.SetEvent(self.hWaitStop)

    # SvcStop only gets triggered when the user explicitly stops (or restarts)
    # the service.  To shut the service down cleanly when Windows is shutting
    # down, we also need to hook SvcShutdown.
    SvcShutdown = SvcStop

    def SvcDoRun(self):

        # log a service started message
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ' (%s)' % self._svc_display_name_))

        while 1:
            self.thread_event = Event()
            self.thread_event.set()
            try:
                self.bottle_srv = BottleWsgiServer(self.thread_event)
                self.bottle_srv.start()
            except Exception, info:
                errmsg = getTrace()
                servicemanager.LogErrorMsg(errmsg)
                self.SvcStop()

            rc = win32event.WaitForMultipleObjects((self.hWaitStop,), 0,
                win32event.INFINITE)
            if rc == win32event.WAIT_OBJECT_0:
                # user sent a stop service request
                self.SvcStop()
                break

        # log a service stopped message
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ' (%s) ' % self._svc_display_name_))


class NullOutput:
    """A stdout / stderr replacement that discards everything."""

    def noop(self, *args, **kw):
        pass
    write = writelines = close = seek = flush = truncate = noop

    def __iter__(self):
        return self

    def next(self):
        raise StopIteration

    def isatty(self):
        return False

    def tell(self):
        return 0

    def read(self, *args, **kw):
        return ''

    readline = read

    def readlines(self, *args, **kw):
        return []


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(BottleService)
