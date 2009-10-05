#!/usr/bin/python


# TODO notes:
#
# - impliment handle_* functions for everything x3 has register fetaures for
# - impliment script load/unload for user scripts.
#       - load a script via this script. 
#       - script calls functions from here to set its functions up for calling on various actions
# - provide helper functions for subscripts to save settings attached to users/chanels
# - provide helper functions for scripts to do common things like msg a person or a channel,
#   reply, etc.

import _svc

import math

import sys


class irc:
    """Used to interact with the world of IRC from module scripts"""

    # some defaults to make shorthand easy
    caller = ''
    target = ''
    service = ''

    def __init__(self, service = None, caller = None, target = None):
        """ Constructor """
        self.caller = caller   #the person who sent the command/message
        self.service = service #the service who saw the message
        self.target = target   #the channel message was in (if public)

    def send_target_privmsg(self, source, target, message):
        _svc.send_target_privmsg(source, target,  "%s "%(message))

    def reply(self, message):
        """ Send a private reply to the user using convenience values"""
        #print "DEBUG: sending a message from %s to %s: %s"%(self.service, self.caller, message)
        if(len(self.target)):
            self.send_target_privmsg(self.service, self.target, "%s: %s"%(self.caller, message))
        else:
            self.send_target_privmsg(self.service, self.caller, message)

class handler:
    """ Main hub of python system. Handle callbacks from c. """

    def __init__(self):
        #print "DEBUG: constructor for handler initing"
        self.plugins = plugins(self)
        if(not self.plugins):
            print "DEBUG: unable to make self.plugins!?!"

    def init(self, irc): # not to be confused with __init__!
        """ This gets called once all the objects are up and running. Otherwise,
        were not done initing this own instance to be able to start calling it """
        #print "DEBUG: in handler.init()"
        self.plugins.init()
        return 0

    def join(self, irc, channel, nick):
        #user = _svc.get_user(nick)
        #print "DEBUG: handler.join()"
        return self.plugins.callhandler("join", irc, [channel, nick], [channel, nick])

    def server_link(self, irc, name, desc):
        return self.plugins.callhandler("server_link", irc, [name, desc], [name, desc])

    def new_user(self, irc, nick, ident, hostname, info):
        # we may filter on all the user fields, but we only pass the nick because
        # the plugin can get the rest itself
        return self.plugins.callhandler("new_user", irc, [nick, ident, hostname, info], [nick])

    def nick_change(self, irc, nick, old_nick):
        return self.plugins.callhandler("nick_change", irc, [nick, old_nick], [nick, old_nick])
        
    def cmd_run(self, irc, cmd):
        #print "DEBUG: handler.cmd_run: %s"%cmd
        eval(cmd)
        return 0

    def addhook(self, event, method, filter=[None], data=None):
        self.plugins.addhook(event, method, filter, data)
        return 0

    def addcommand(self, plugin, command, method):
        self.addhook("command", method, [plugin, command])

    def cmd_command(self, irc, plugin, cmd, args):
        #print "DEBUG: handel.cmd_command; %s %s; args= %s"%(plugin, cmd, args)
        return self.plugins.callhandler("command", irc, [plugin, cmd], [args])

    def load(self, irc, plugin):
        return self.plugins.load(plugin)

class plugins:
    """Class to handle loading/unloading of plugins"""
    loaded_plugins = {}
    hooks = []

    class hook:
        """ This is a request from a plugin to be called on an event """
        event = ""     # Event to be called on (eg "join")
        method = None  # Method to call
        filter = None  # Arguments to filter
        data = ""      # plugin-supplied data for plugin use
        
        def __init__(self, event, method, filter, data):
            self.event = event
            self.method = method
            self.filter = filter
            self.data = data

        def event_is(self, event, evdata):
            if(self.event == event):
                for i in range(len(self.filter)):
                    if( self.filter[i] != None 
                      and self.filter[i] != evdata[i]): # should be case insensitive? or how to compare?
                        #print "DEBUG: rejecting event, %s is not %s"%(self.filter[i], evdata[i])
                        return False
                return True
            else:
                return False

        def trigger(self, irc, args):
            #print "DEBUG: Triggering %s event. with '%s' arguments."%(self.event, args)
            self.method(irc, *args)

    def __init__(self, handler):
        """ Constructor """
        #print "DEBUG: constructor for plugins initing"
        self.handler = handler

    def init(self):
        #print "DEBUG: in plugins.init()"
        self.load("annoy")
        self.load("hangman")

    def addhook(self, event, method, filter=[None], data=None):
        #print "DEBUG: Adding hook for %s."%event
        self.hooks.append(self.hook(event, method, filter, data))

    def findhooksforevent(self, event, data):
        ret = []
        #print "DEBUG: findhooksforevent() looking..."
        for hook in self.hooks:
            #print "DEBUG: looking at a %s hook..."%hook.event
            if(hook.event_is(event, data)):
                ret.append(hook)
        return ret

    def callhandler(self, event, irc, filter, args):
        for hook in self.findhooksforevent(event, filter):
            if(hook.trigger(irc, args)):
                return 1
        return 0

    def load(self, name):
        """ Loads a plugin by name """
        mod_name = "plugins.%s"%name
        need_reload = False
        if(sys.modules.has_key(mod_name)):
            need_reload = true
        #TODO: try to catch compile errors etc.

        if(need_reload == False):
            __import__(mod_name)
        module = sys.modules[mod_name]
        if(need_reload == True):
            reload(module) # to ensure its read fresh
        Class = module.Class
        pluginObj = Class(self.handler, irc())
        self.loaded_plugins[mod_name] = pluginObj
        return True

