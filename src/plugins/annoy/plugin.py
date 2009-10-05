# anoy module

import _svc

class Annoy:

    def __init__(self, handler, irc):
        self.handler = handler
        self.name = "annoy"

#       These hooks are for testing, and are commented out by default so as not to annoy
#       us unless we want to test them
        #handler.addhook("join", self.on_join, "foobar")
        #handler.addhook("nick_change", self.nick_change, ["Rubin", None], "testing")

        handler.addcommand(self.name, "dance", self.dance)
        handler.addcommand(self.name, "nickof", self.nickof)
        self.test = "footest"

#    def on_join(self, irc, channel, nick):
#        irc.send_target_privmsg("x3", channel, "%s joined %s:%s "%(nick, channel, self.test))

    def nick_change(self, irc, nick, old_nick):
        svcinfo = _svc.get_info()
        # opserv pm #theops that someones nick changed
        irc.send_target_privmsg(svcinfo["opserv"], "#theops", "%s changed nick to %s"%(old_nick, nick) )

    def dance(self, irc, args):
        nick = irc.caller
        user = _svc.get_user(nick)

        reply = "Ok,"
        if(user and "account" in user):
           reply +=  " Mr. %s"%user["account"]

        reply += " we can dance"
        if(len(args)):
            reply += " "
            reply += args
        reply += "."

        irc.reply(reply)

    def nickof(self, irc, bot):
        info = _svc.get_info()

        if(bot and bot in info.keys()):
            irc.reply("%s has nick %s"%(bot, info[bot]))
        else:
            irc.reply("I dunno. Try %s"%str(info.keys()))

Class = Annoy
