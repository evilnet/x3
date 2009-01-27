# anoy module

import svc

class Annoy:

    def __init__(self, handler, irc):
        self.handler = handler
        self.name = "annoy"

#        irc.send_target_privmsg("O3", "#TheOPS", "%s is loaded"%self.name)
#        handler.addhook("join", self.on_join, "foobar")
        handler.addcommand(self.name, "dance", self.dance)
        self.test = "footest"

#    def on_join(self, irc, channel, nick):
#        irc.send_target_privmsg("x3", channel, "%s joined %s:%s "%(nick, channel, self.test))

    def dance(self, irc, args):
        nick = irc.caller
        user = svc.get_user(nick)

        reply = "Ok,"
        if(user and "account" in user):
           reply +=  " Mr. %s"%user["account"]

        reply += " we can dance"
        if(len(args)):
            reply += " "
            reply += args
        reply += "."

        irc.reply(reply)

Class = Annoy
