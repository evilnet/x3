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

import svc

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
        svc.send_target_privmsg(source, target,  "%s "%(message))

    def reply(self, message):
        """ Send a private reply to the user using convenience values"""
        print "DEBUG: sending a message from %s to %s: %s"%(self.service, self.caller, message)
        if(self.target):
            self.send_target_privmsg(self.service, self.target, "%s: %s"%(self.caller, message))
        else:
            self.send_target_privmsg(self.service, self.caller, message)

class handler:
    """ Main hub of python system. Handle callbacks from c. """
    modules = None  #module object to deal with 

    def init(self, irc): # not to be confused with __init__!
        print "DEBUG: This is x3init in python"
        self.modules = modules()
        return 0

    def join(self, irc, channel, nick):
        user = svc.get_user(nick)
        print "DEBUG: handler.join()"
        irc.send_target_privmsg("x3", channel, "%s joined %s: %s "%(nick, channel, user))
        return 0
        
    def cmd_run(self, irc, cmd):
        print "DEBUG: handler.cmd_run: %s"%cmd
        eval(cmd);
        return 0;

class modules:
    """Class to handle loading/unloading of modules"""
    loaded_modules = {}

    def __init__(self):
        self.load("annoy")

    def load(self, name):
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
        pluginObj = Class(irc())
        self.loaded_modules[mod_name] = pluginObj

       
