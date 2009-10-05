# anoy module

import _svc
import re
import fileinput
import random

# HANGMAN !!!!
# /---
# |  o
# | /|\
# | / \
# =======

class Game:
    target = '' #channel or user's nick who we are playing with
    word = ''
    maskchar = '*'
    man = 0
    dictionary = "/usr/share/dict/words"

    def __init__(self, irc, target, length=0):
        self.irc = irc
        self.target = target
        length = int(length)
        if(length > 3 and length < 100):
            self.length = length
        else:
            self.length = random.randrange(5, 9)
        # What constitutes a valid word?
        self.valid = re.compile(r"^[a-zA-Z]+$")
        self.guesses = {}

        if(self.length < 3):
            self.reply("You can only play with 3 or more letters")
            self.man = 9999
            return

        if(self.newword(self.length)):
            self.reply("HANGMAN is starting!")
            self.printstatus()
        else:
            self.reply("Aborting game")
            self.man = 9999
            return 

    def validword(self):
        if(len(self.word) == self.length and self.valid.search(self.word)):
                return True
        return False

    def newword(self, length):
        numlines = 0
        for line in open(self.dictionary, "r"):
          numlines += 1
        tries = 0

        if(numlines < 100):
            raise Exception("Dictionary has too few words")

        while((not self.validword())): #failsafe dont loop forever...
            tries += 1
            if(tries > 10):
                self.reply("Error finding a %s letter word"%length)
                return False
                #raise(Exception("DictError", "Unable to find %s letter word"%length))
            i = 0
            randline = random.randrange(1, numlines-1)
            for line in open(self.dictionary, 'r'):
                if(i >= randline):
                    self.word = line.rstrip()
                    if(not self.validword() and i < randline + 50):
                        continue
                    else:
                        break # give up on this block and try again
                i += 1
        if(len(self.word) < 3):
            self.reply("Unable to find a word in the dictionary!")
            return False

        return True


    def maskedword(self):
        mask = []
        for i in self.word:
            if(i in self.guesses or not i.isalpha()):
                mask.append(i)
            else:
                mask.append(self.maskchar)
        return(''.join(mask))

    def manpart(self, part, num):
        if(self.man >= num):
            return part
        else:
            return " "

    def printstatus(self):
        print("DEBUG: the word is '%s'"%self.word)
        self.reply(" /---%s       "%( self.manpart(",", 1 )) )
        self.reply(" |   %s       Make "%( self.manpart("o",2)) )
        self.reply(" |  %s%s%s      your "%( self.manpart("/",4), self.manpart("|",3), self.manpart("\\", 5) ) )
        self.reply(" |  %s %s      guess! "%( self.manpart("/",6), self.manpart("\\",7) ))
        self.reply(" ====")
        self.reply(self.maskedword())

        if(self.won() == True):
            self.reply("YOU WON! FOR NOW!!")
        elif(self.won() == False):
            self.reply("Your DEAD! DEAAAAAAAD!")


    def won(self):
        if(self.man >= 7):
            return False

        for i in self.word:
            if(not i in self.guesses.keys()):
                return None
        return True

    def guess(self, irc, letter):
        self.irc = irc

        if(self.won() != None):
            self.reply("This game is over. Start another!")
            return
        if(len(letter) > 1):
            self.reply("Guess a single letter only, please.")
            return
        if(not letter.isalpha()):
            self.reply("Letters only. Punctuation will be filled in for you.")
            return
        if(letter in self.guesses):
            self.reply("Pay attention! %s has already been guessed! I'm hanging you anyway!"%letter)
            self.man += 1
            self.printstatus()
            return
        
        self.guesses[letter] = True

        if(self.won() != None):
            pass
        elif(self.word.find(letter) >= 0):
            self.reply("YOU GOT ONE! But I'll hang you yet!!")
        else:
            self.reply("NO! MuaHaHaHaHa!")
            self.man += 1

        self.printstatus()

    def reply(self, msg):
            self.irc.send_target_privmsg(self.irc.service, self.target, msg)

class Hangman:
    config = {}

    def __init__(self, handler, irc):
        self.handler = handler
        self.name = "hangman"

        handler.addcommand(self.name, "start", self.start)
        handler.addcommand(self.name, "end", self.end)
        handler.addcommand(self.name, "guess", self.guess)

        self.games = {} # list of game objects

    def target(self, irc):
        if(len(irc.target)):
            return irc.target
        else:
            return irc.caller 

    def start(self, irc, arg):
        playwith = self.target(irc)
        if(playwith in self.games.keys() and self.games[playwith].won() == None):
            irc.reply("There is a game is in progress here, End it before you start another.")
            return
            
        if(arg.isdigit()):
            self.games[playwith] = Game(irc, playwith, arg)
        else:
            self.games[playwith] = Game(irc, playwith)

    def end(self, irc, unused):
        playwith = self.target(irc)
        if(self.target(irc) in self.games.keys()):
            self.games[playwith].reply("Game ended by %s"%irc.caller)
            del(self.games[playwith])
        else:
            irc.reply("No game here to end")

    def guess(self, irc, arg):
        playwith = self.target(irc)
        if(self.target(irc) in self.games.keys()):
            self.games[playwith].guess(irc, arg)
        else:
            irc.reply("No game here in progress. Start one!")

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

Class = Hangman
