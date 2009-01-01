Using translations:
  copy the languages folder into your x3 runtime directory, and restart x3.
  alternate languages will be available in /msg authserv set lanugage
  NOTE: Currently no other languages are caught up to recent development. 
  if you speak them, please see below for updating instructions.

Translating:
Thanks for your interest in helping to translate X3 to other languages.

How to make a new language:

1: run the export script, to make an up-to-date "C" baseline db:
   ./lang_export.sh > strings.db
2: make a dir for your language such as de/
   mkdir fo
3: copy thi strings.db into your new dir
   cp strings.db fo
4: copy the help files into your new dir
   cp ../src/*.help fo
5: edit the .help and .db files, translating them to your laungage.
   nano fo/strings.db  (etc)
6: test the strings.db file
   ./validate.pl fo
7: fix any problems.


How to keep your language up to date after changes:

1: run the export script, to make an up-to-date "C" baseline db:
   ./lang_export.sh > strings.db
2: test the strings.db file
   ./validate.pl fo
3: fix any changes.

You should also watch the cvs mailing list for changes in meaning of the strings
since X3 is under active development.


