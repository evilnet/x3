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


class modules:
    """Class to handle loading/unloading of modules"""
    loaded_modules = []

    def load(self, name):
        mod_name = "plugins.%s"%name
        if(sys.modules[mod_name]):
            need_reload = true
        #TODO: try to catch compile errors etc.
        if(!need_reload):
            __import__(mod_name)
        module = sys.modules[mod_name]
        if(need_reload):
            reload(module) # to ensure its read fresh
        self.loaded_modules[mod_name] = module

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
        self.send_target_privmsg(self.service, self.caller, message)


    def command_set(self, command_caller, command_target, command_service):
        """ Setup defaults for convenience"""
        global caller, target, service
        caller = command_caller
        target = command_target
        service = command_service
        return 0;

    def command_clear(self):
        """ Clear convenience defaults"""
        global caller, target, service
        caller = None
        target = None
        service = None
        return 0;


class handler:
    """ Handle callbacks """

    def init(): # not to be confused with __init__!
        print "DEBUG: This is x3init in python"
        return 0

    def join(self, channel, nick)
        user = svc.get_user(nick)
        irc.send_target_privmsg("x3", channel, "test %s "%(service))
        
#+print "This is mod-python.py"
#+
#+caller = ''
#+target = ''
#+service = ''
#+
#+def handle_init():
#+    print "This is x3init in python"
#+    return 0
#+
#+
#+def handle_join(channel, nick):
#+    global caller, target, service
#+    print "This is handle_join() in python"
#+    user = svc.get_user(nick)
#+    svc.send_target_privmsg("x3", channel, "test %s "%(service))
#+    svc.send_target_privmsg("x3", channel, "   %s joined %s: %s"%(nick, channel, user))
#+    svc.send_target_privmsg("x3", channel, "Welcome to %s %s (*%s)! Your IP is %s. You are now in %d channels!"%(channel, user['nick'], user['account'], user['ip'], len(user['channels']) ))
#+    chan = svc.get_channel(channel)
#+    svc.send_target_privmsg("x3", channel, "Channel details: %s"%chan)
#+    return 0
#+
#+def run(command):
#+    eval(command)
#+    return 0
#+
#+def reply(message):
#+    global caller, target, service
#+    print "DEBUG: %s / %s / %s : %s" %(caller, target, service, message);
#+    if(len(target) > 0):
#+        svc.send_target_privmsg(service, target, "%s: %s"%(caller, message));
#+    else:
#+        svc.send_target_notice(service, caller, message);
#+    return 0
