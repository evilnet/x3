# anoy module

import svc

class Annoy:

    def __init__(self, handler, irc):
        self.handler = handler
        self.name = "annoy"

        irc.send_target_privmsg("O3", "#TheOPS", "%s is loaded"%self.name)
        handler.addhook("join", self.on_join, "foobar")
        handler.addcommand(self.name, "dance", self.dance)
        self.test = "footest"

    def on_join(self, irc, channel, nick):
        irc.send_target_privmsg("x3", channel, "%s joined %s:%s "%(nick, channel, self.test))

    def dance(self, irc, args):
        irc.reply("Ok, %s, we can dance %s."%(irc.caller, args))

Class = Annoy
