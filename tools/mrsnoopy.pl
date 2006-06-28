#!/usr/bin/perl -w

# Author: rubin@afternet.org irc.afternet.org/#afternet

$script_version = "0.3";
$script_name = "MrSnoopy's magic color kit v$script_version";
$version = IRC::get_info(0);
# get a string of the form 1.2.0 or 1.3.3
$version =~ s/\.//g;
if ($version >= 120) {
  IRC::register("MrSnoopy's magic color kit", $script_version, "", "");
}

IRC::add_message_handler("PRIVMSG",    "IRC::Xchat::MrSnoopy::privmsg_handler");  # msgs

package IRC::Xchat::MrSnoopy;

IRC::print "\0032SNOOPY: \003\tLoading $script_name...\n";

$color_darkgreen = '03';
$color_darkblue  = '02';
$color_white = '00';
$color_black = '01';
$color_red   = '04';
$color_darkred = '05';
$color_darkmajenta = '06';
$color_darkyellow = '07';
$color_yellow = '08';
$color_green = '09';
$color_darkcyan = '10';
$color_cyan = '11';
$color_blue = '12';
$color_majenta = '13';
$color_darkgrey = '14';
$color_grey = '15';

$dronename_file = $ENV{'HOME'}."/.xchat2/drones.txt";

# Load pendrone names
#----------------------
my %DroneNames;
my $line = "";
open PENFILE, "<$dronename_file" or IRC::print "\0032SNOOPY: \003\t   Error opening $dronename_file\n";
while(<PENFILE>)
{
    chomp;
    $line .= $_;
}
@lines = split /\n/, $line;
foreach $line (@lines)
{
    $DroneNames{"$line"} = 1;
#    IRC::print "Adding penDrone name '$line'\n";
}
#----------------------
$count = 0 + %DroneNames;
IRC::print "\0032SNOOPY: \003\t   Added $count names from drone file $dronename_file\n";

sub privmsg_handler
{
  local($cmds) = @_;
  $cmds =~ /\:(\S+)\s+PRIVMSG\s+(\S+)\s+\:(.*)/;
  $source = $1;
  $target = $2;
  $msg = $3;

  if($target =~ /\#MrSnoopy/)
  {
      $source =~ /(\S+)\!(\S+)\@(\S+)/;
      $snick = $1;
      $suname = $2;
      $shost = $3;

      # [15:14:10] QUIT efggv (KIM666@82-35-112-226.cable.ubr07.dals.blueyonder.co.uk, on Gamesleague.NL.Afternet.Org) (Quit)
      if($msg =~ /(\[[^]]+\])\W+(\w+)\W+ (.+)/)
      {
         $time = $1;
         $note_type = $2;
         $message = $3;

         if($note_type =~ /(JOIN)/)
         {
            $message =~ /(\S+)\sby\s(\S+)/;
            $chan = $1;
            $nick = $2;
            IRC::print "$time \003".$color_darkyellow."   JOIN\t$nick joined \003$color_darkyellow$chan\003\n";
         }
         elsif($note_type =~ /(CREATE)/)
         {
            $message =~ /(\S+)\sby\s(\S+)/;
            $chan = $1;
            $nick = $2;
            IRC::print "$time \003".$color_darkyellow." CREATE\t$nick joined $chan\003\n";
         }
	 elsif($note_type =~ /PART/)
         {
            $message =~ /(\S+)\sby\s(\S+)/;
            $chan = $1;
            $nick = $2;
            IRC::print "$time \003".$color_darkmajenta."   PART\t$nick left $chan\003\n";
         }
         elsif($note_type =~ /NICK/)
         {
            # Armagedon|RoA-afk Armagedon_@c56-151.icpnet.pl () [62.21.56.151] on Airspace.US.AfterNET.Org
            if($message =~ /(\S+)\s([^@]+)\@(\S+)\s\(([^)]*)\)\s\[([^]]+)\]\son\s(\S+)/)
            {
                $nick = sprintf("%-15s", $1);
                #$user = sprintf("%10s", $2);
                $user = $2;
                $host = $3;
                $account = $4;
                $ip = sprintf("%15s", $5);
                $server = $6;
                #IRC::print "$time \003".$color_green."CONNECT\t[\003$color_blue$ip\003$color_green] as $nick \003$color_darkcyan$user\003$color_grey@\003$color_darkcyan$host \003$color_green(\003$color_yellow$account\003$color_green)  on $server\n";
                IRC::print "$time \003".$color_green."CONNECT\t$nick (\003$color_darkcyan$user\003$color_grey@\003$color_darkcyan$host\003$color_green) \003$color_yellow*$account\003$color_green [\003$color_blue$ip\003$color_green]  on $server\003\n";
                #if(exists $DroneNames{$1})
                if(exists $DroneNames{$1} && exists $DroneNames{$2} && !($1 eq $2))
                {
                    IRC::print "\0032SNOOPY: \003\t$time \003".$color_red."!!!!! '$1' is a drone!\n";
                    IRC::command "/MSG #Operations .drone $1 AUTO";
                }
                #else
                #{
                    #IRC::print "\003".$color_green."       \t '$1' Not a drone\n";
                #}
            }
	    #[21:32:45] NICK change Lil_JJ -> [-BDC-]J_Word
	    elsif($message =~ /change (\S+)\s\-\>\s(\S+)/)
	    {
		    $old = $1;
		    $new = $2;
		    IRC::print "$time \003".$color_darkgreen."  NICK\t$old is now known as $new\003\n";
		    return 1;
	    }
            else
            {
               return 0;
            }
         }
         elsif($note_type =~ /QUIT/)
         {
            # InvaderC1 (Chadwick@adsl-67-125-1-144.dsl.scrm01.pacbell.net, on Gamesleague.NL.Afternet.Org) (Ping timeout)
            #OR - QUIT Nader (supybot@CPE-72-131-73-97.mn.res.rr.com, on Pyro.US.AfterNET.Org) (Killed (Rubin (testing snoop)))
            #OR - no "killed" at all? WTF is up with snoop and kills. 
            $message =~ /(\S+)\s\(([^@]+)\@([^,]+)\,\son\s(\S+)\)\s\((Killed|)(.+)\)/;
            $nick = sprintf("%-15s", $1);
            $user = $2;
            $host = $3;
            $server = $4;
            $killed = $5;
            $quitmsg = $6;
            IRC::print "$time \003".$color_darkred."   QUIT\t$nick (\003$color_darkgrey$user\003$color_grey@\003$color_darkgrey$host\003$color_darkred) on $server (\003$color_white$quitmsg\003$color_darkred)\003 [$killed]\n";
            #return 0; # debug
         }
	 elsif($note_type=~/UMODE/)
	 {
            #Walter +rx Walter 
            if($message =~ /(\S+)\s+(.+)\s*(\S*)/)
            {
                    $nick = $1;
                    $mode = $2;

                    IRC::print "$time \003".$color_darkgrey."  UMODE\t$nick \002$mode\002 $nick\003\n";
            }
            else
            {
                    return 0;
            }
	 }
         elsif($note_type =~/MODE/)
         {
            # afternet +l 12 by X3
            if($message =~ /\s*(\S+)\s+(.+)\sby\s(\S+)/)
	    {
		    $channel = $1;
		    $mode = $2;
		    $nick = $3;
		    IRC::print "$time \003$color_grey   MODE\t$nick set \002$mode\002 on $channel\003\n";
	    }
	    else
	    {
		    return 0;
	    }
         }
         elsif($note_type =~ /AUTH/)
         {
                 #teclis as cehb
                 $message =~ /(\S+)\sas\s(\S+)/;
                 $nick = $1;
                 $account = $2;
                 IRC::print "$time \003$color_darkgreen   AUTH\t$nick as \003$color_yellow*$account\003\n";
         }
         elsif($note_type =~ /KILL/)
         {
                 #Sore (mem0ry@Toronto-HSE-ppp3667456.sympatico.ca, on Pyro.US.AfterNET.Org) by AuthServ (Ghost kill on account Sorea (requested by Eros).)
                 if($message =~ /(\S+)\s\(([^@]+)\@([^,]+)\,\son\s(\S+)\)\sby\s(\S+)\s(.*)\)/)
                 {
                     $nick = $1;
                     $user = $2;
                     $host = $3;
                     $server = $4;
                     $killer = $5;
                     $message = $6;
                     IRC::print "$time \003".$color_darkred."   KILL\t$nick (\003$color_darkgrey$user\003$color_grey@\003$color_darkgrey$host\003$color_darkred) on $server by $killer (\003$color_white$quitmsg\003$color_darkred)\003\n";

                 }
                 else
                 {
                     return 0;
                 }
         }
         else
         {
	    #didnt understand it, just let xchat print it
            return 0;
         }
         # Successfully handled it, return handled
         return 1;
      }
      else
      {
         #IRC::print "'$msg' didnt match\n";
         return 0;
      }
  }

  return 0;
}
IRC::print "\0032SNOOPY: \003\t...Done\n";
1;
_END_

