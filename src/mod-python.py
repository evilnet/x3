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

print "This is mod-python.py"

def handle_init():
    print "This is x3init in python"
    return 0

def handle_join(channel, nick):
    print "This is handle_join() in python"
    user = svc.get_user(nick)
    svc.send_target_privmsg("x3", channel,  "   %s joined %s: %s"%(nick, channel, user))
    svc.send_target_privmsg("x3", channel, "Welcome to %s %s (*%s)! Your IP is %s. You are now in %d channels!"%(channel, user['nick'], user['account'], user['ip'], len(user['channels']) ))
    chan = svc.get_channel(channel)
    svc.send_target_privmsg("x3", channel, "Channel details: %s"%chan)
    return 0


