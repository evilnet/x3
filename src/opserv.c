/* opserv.c - IRC Operator assistance service
 * Copyright 2000-2004 srvx Development Team
 *
 * This file is part of x3.
 *
 * x3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with srvx; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include "config.h"
#include "chanserv.h"
#include "conf.h"
#include "common.h"
#include "gline.h"
#include "global.h"
#include "nickserv.h"
#include "modcmd.h"
#include "modules.h"
#include "proto.h"
#include "opserv.h"
#include "timeq.h"
#include "saxdb.h"
#include "shun.h"

#include <tre/regex.h>

#ifdef HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#define OPSERV_CONF_NAME "services/opserv"

#define KEY_ALERT_CHANNEL "alert_channel"
#define KEY_ALERT_CHANNEL_MODES "alert_channel_modes"
#define KEY_DEBUG_CHANNEL "debug_channel"
#define KEY_DEBUG_CHANNEL_MODES "debug_channel_modes"
#define KEY_UNTRUSTED_MAX "untrusted_max"
#define KEY_PURGE_LOCK_DELAY "purge_lock_delay"
#define KEY_JOIN_FLOOD_MODERATE "join_flood_moderate"
#define KEY_JOIN_FLOOD_MODERATE_THRESH "join_flood_moderate_threshold"
#define KEY_NICK "nick"
#define KEY_JOIN_POLICER "join_policer"
#define KEY_NEW_USER_POLICER "new_user_policer"
#define KEY_AUTOJOIN_CHANNELS "autojoin_channels"
#define KEY_REASON "reason"
#define KEY_RESERVES "reserves"
#define KEY_IDENT "username" /* for compatibility with 1.0 DBs */
#define KEY_HOSTNAME "hostname"
#define KEY_DESC "description"
#define KEY_BAD_WORDS "bad"
#define KEY_EXEMPT_CHANNELS "exempt"
#define KEY_SECRET_WORDS "secret"
#define KEY_TRUSTED_HOSTS "trusted"
#define KEY_OWNER "owner"
#define KEY_GAGS "gags"
#define KEY_ALERTS "alerts"
#define KEY_REACTION "reaction"
#define KEY_DISCRIM "discrim"
#define KEY_WARN "chanwarn"
#define KEY_MAX "max"
#define KEY_TIME "time"
#define KEY_LAST "last"
#define KEY_MAX_CLIENTS "max_clients"
#define KEY_LIMIT "limit"
#define KEY_EXPIRES "expires"
#define KEY_STAFF_AUTH_CHANNEL "staff_auth_channel"
#define KEY_STAFF_AUTH_CHANNEL_MODES "staff_auth_channel_modes"
#define KEY_CLONE_GLINE_DURATION "clone_gline_duration"
#define KEY_BLOCK_GLINE_DURATION "block_gline_duration"
#define KEY_BLOCK_SHUN_DURATION "block_shun_duration"
#define KEY_ISSUER "issuer"
#define KEY_ISSUED "issued"
#define KEY_ADMIN_LEVEL "admin_level"
#define KEY_SILENT_LEVEL "silent_level"
#define KEY_UPLINK "uplink"
#define KEY_SECOND "secondaryuplink"
#define KEY_PORT "port"
#define KEY_KARMA "karma"
#define KEY_OFFLINE "offline"
#define KEY_ROUTINGPLAN "routingplan"
#define KEY_ROUTINGPLAN_OPTIONS "routingplan_options"
#define KEY_DEFCON1 "DefCon1"
#define KEY_DEFCON2 "DefCon2"
#define KEY_DEFCON3 "DefCon3"
#define KEY_DEFCON4 "DefCon4"
#define KEY_DEFCON_LEVEL "DefConLevel"
#define KEY_DEFCON_CHANMODES "DefConChanModes"
#define KEY_DEFCON_SESSION_LIMIT "DefConSessionLimit"
#define KEY_DEFCON_TIMEOUT "DefConTimeOut"
#define KEY_DEFCON_GLOBAL "GlobalOnDefcon"
#define KEY_DEFCON_GLOBAL_MORE "GlobalOnDefconMore"
#define KEY_DEFCON_MESSAGE "DefconMessage"
#define KEY_DEFCON_OFF_MESSAGE "DefConOffMessage"
#define KEY_DEFCON_GLINE_DURATION "DefConGlineExpire"
#define KEY_DEFCON_GLINE_REASON "DefConGlineReason"

/* Routing karma values: */
/* What value we start out with when new servers are added: */
#define KARMA_DEFAULT 10
 /* max, min */
#define KARMA_MAX 10
#define KARMA_MIN -10
/* ping out, reduce karma by this much: */
#define KARMA_PINGOUT -8
/* read err, reduce karma by this much: */
#define KARMA_READERROR -5
/* every 24 hours everyone gets this much added (so we eventually re-try bad servers) */
#define KARMA_ENTROPE 1
/* every 24 hours servers linked for 24 hours get an additional ammount: */
#define KARMA_RELIABLE 1
/* How often to run entrope and reliable checks */
#define KARMA_TIMER 86400 /* 1 day */

#define ROUTING_CONNECT_TIMEOUT 30 /* 30 seconds */

#define IDENT_FORMAT            "%s [%s@%s/%s]"
#define IDENT_DATA(user)        user->nick, user->ident, user->hostname, irc_ntoa(&user->ip)
#define MAX_CHANNELS_WHOIS      50
#define OSMSG_PART_REASON       "%s has no reason."
#define OSMSG_KICK_REQUESTED    "Kick requested by %s."
#define OSMSG_KILL_REQUESTED    "Kill requested by %s."
#define OSMSG_GAG_REQUESTED     "Gag requested by %s."

static const struct message_entry msgtab[] = {
    { "OSMSG_BAR", "----------------------------------------" },
    { "OSMSG_USER_ACCESS_IS", "$b%s$b (account $b%s$b) has %d access." },
    { "OSMSG_LEVEL_TOO_LOW", "You lack sufficient access to use this command." },
    { "OSMSG_NEED_CHANNEL", "You must specify a channel for $b%s$b." },
    { "OSMSG_INVALID_IRCMASK", "$b%s$b is an invalid IRC hostmask." },
    { "OSMSG_ADDED_BAN", "I have banned $b%s$b from $b%s$b." },
    { "OSMSG_SHUN_ISSUED", "Shun issued for $b%s$b." },
    { "OSMSG_SHUN_REMOVED", "Shun removed for $b%s$b." },
    { "OSMSG_SHUN_FORCE_REMOVED", "Unknown/expired Shun removed for $b%s$b." },
    { "OSMSG_SHUN_ONE_REFRESHED", "All Shuns resent to $b%s$b." },
    { "OSMSG_SHUN_REFRESHED", "All Shuns refreshed." },
    { "OSMSG_GLINE_ISSUED", "G-line issued for $b%s$b." },
    { "OSMSG_GLINE_REMOVED", "G-line removed for $b%s$b." },
    { "OSMSG_GLINE_FORCE_REMOVED", "Unknown/expired G-line removed for $b%s$b." },
    { "OSMSG_GLINES_ONE_REFRESHED", "All G-lines resent to $b%s$b." },
    { "OSMSG_GLINES_REFRESHED", "All G-lines refreshed." },
    { "OSMSG_CLEARBANS_DONE", "Cleared all bans from channel $b%s$b." },
    { "OSMSG_CLEARMODES_DONE", "Cleared all modes from channel $b%s$b." },
    { "OSMSG_NO_CHANNEL_MODES", "Channel $b%s$b had no modes to clear." },
    { "OSMSG_DEOP_DONE", "Deopped the requested lusers." },
    { "OSMSG_DEOPALL_DONE", "Deopped everyone on $b%s$b." },
    { "OSMSG_DEHOP_DONE", "Dehalfopped the requested lusers." },
    { "OSMSG_DEHOPALL_DONE", "Dehalfopped everyone on $b%s$b." },
    { "OSMSG_NO_DEBUG_CHANNEL", "No debug channel has been configured." },
    { "OSMSG_INVITE_DONE", "Invited $b%s$b to $b%s$b." },
    { "OSMSG_ALREADY_THERE", "You are already in $b%s$b." },
    { "OSMSG_USER_ALREADY_THERE", "%s is already in $b%s$b." },
    { "OSMSG_NOT_THERE", "You not in $b%s$b." },
    { "OSMSG_JOIN_DONE", "I have joined $b%s$b." },
    { "OSMSG_MARK_SET", "Set the MARK." },
    { "OSMSG_SVSJOIN_SENT", "Sent the SVSJOIN." },
    { "OSMSG_SVSPART_SENT", "Sent the SVSPART." },
    { "OSMSG_ALREADY_JOINED", "I am already in $b%s$b." },
    { "OSMSG_NOT_ON_CHANNEL", "$b%s$b does not seem to be on $b%s$b." },
    { "OSMSG_KICKALL_DONE", "I have cleared out %s." },
    { "OSMSG_LEAVING", "Leaving $b%s$b." },
    { "OSMSG_MARK_INVALID", "Sorry, marks must contain only letters, numbers, and dashes ('-')." },
    { "OSMSG_MODE_SET", "I have set the modes for $b%s$b." },
    { "OSMSG_OP_DONE", "Opped the requested lusers." },
    { "OSMSG_OPALL_DONE", "Opped everyone on $b%s$b." },
    { "OSMSG_HOP_DONE", "Halfopped the requested lusers." },
    { "OSMSG_HOPALL_DONE", "Halfopped everyone on $b%s$b." },
    { "OMSG_BAD_SVSNICK", "$b%s$b is an invalid nickname." },

    { "OSMSG_WHOIS_IDENT",      "%s (%s@%s) from %d.%d.%d.%d" },
    { "OSMSG_WHOIS_NICK",       "Nick         : %s" },
    { "OSMSG_WHOIS_HOST",       "Host         : %s@%s" },
    { "OSMSG_WHOIS_FAKEHOST",   "Fakehost     : %s" },
    { "OSMSG_WHOIS_CRYPT_HOST", "Crypt Host   : %s" },
    { "OSMSG_WHOIS_CRYPT_IP",   "Crypt IP     : %s" },
    { "OSMSG_WHOIS_IP",         "Real IP      : %s" },
    { "OSMSG_WHOIS_COUNTRY",    "Country      : %s" },
   { "OSMSG_WHOIS_COUNTRY_CODE","Country Code : %s" },
    { "OSMSG_WHOIS_CITY",       "City         : %s" },
    { "OSMSG_WHOIS_REGION",     "Region/State : %s" },
    { "OSMSG_WHOIS_POSTAL_CODE","Postal Code  : %s" },
    { "OSMSG_WHOIS_LATITUDE",   "Latitude     : %f" },
    { "OSMSG_WHOIS_LONGITUDE",  "Longitude    : %f" },
    { "OSMSG_WHOIS_MAP",        "Map          : %s" },
    { "OSMSG_WHOIS_DMA_CODE",   "DMA Code     : %d" },
    { "OSMSG_WHOIS_AREA_CODE",  "Area Code    : %d" },
    { "OSMSG_WHOIS_MODES",      "Modes        : +%s " },
    { "OSMSG_WHOIS_INFO",       "Info         : %s" },
    { "OSMSG_WHOIS_NUMERIC",    "Numnick      : %s" },
    { "OSMSG_WHOIS_SERVER",     "Server       : %s" },
    { "OSMSG_WHOIS_NICK_AGE",   "Nick Age     : %s" },
    { "OSMSG_WHOIS_ACCOUNT",    "Account      : %s" },
    { "OSMSG_WHOIS_PRIVS",      "IRCd Privs   : %s" },
    { "OSMSG_WHOIS_CHANNELS",   "Channels     : %s" },
    { "OSMSG_WHOIS_HIDECHANS",  "Channel list omitted for your sanity." },
    { "OSMSG_WHOIS_VERSION",    "Version      : %s" },  
    { "OSMSG_WHOIS_MARK",       "Mark         : %s" },  
    { "OSMSG_WHOIS_NO_NOTICE",  "No_notices   : %s" },
    { "OSMSG_UNBAN_DONE", "Ban(s) removed from channel %s." },
    { "OSMSG_CHANNEL_VOICED", "All users on %s voiced." },
    { "OSMSG_CHANNEL_DEVOICED", "All voiced users on %s de-voiced." },
    { "OSMSG_BAD_MODIFIER", "Unknown bad-word modifier $b%s$b." },
    { "OSMSG_BAD_REDUNDANT", "$b%s$b is already covered by a bad word ($b%s$b)." },
    { "OSMSG_BAD_GROWING", "Replacing bad word $b%s$b with shorter bad word $b%s$b." },
    { "OSMSG_BAD_NUKING", " .. and removing redundant bad word $b%s$b." },
    { "OSMSG_ADDED_BAD", "Added $b%s$b to the bad-word list." },
    { "OSMSG_REMOVED_BAD", "Removed $b%s$b from the bad-word list." },
    { "OSMSG_NOT_BAD_WORD", "$b%s$b is not a bad word." },
    { "OSMSG_ADDED_EXEMPTION", "Added $b%s$b to the bad-word exemption list." },
    { "OSMSG_ADDED_EXEMPTIONS", "Added %d exception(s) to the bad word list." },
    { "OSMSG_REMOVED_EXEMPTION", "Removed $b%s$b from the exemption list." },
    { "OSMSG_NOT_EXEMPT", "$b%s$b is not on the exempt list." },
    { "OSMSG_ALREADY_TRUSTED", "Host $b%s$b is already trusted (use $bdeltrust$b and then $baddtrust$b to adjust)." },
    { "OSMSG_NOT_TRUSTED", "Host $b%s$b is not trusted." },
    { "OSMSG_BAD_IP", "$b%s$b is not a valid IP address" },
    { "OSMSG_BAD_NUMBER", "$b%s$b is not a number" },
    { "OSMSG_ADDED_TRUSTED", "Added trusted hosts to the trusted-hosts list." },
    { "OSMSG_UPDATED_TRUSTED", "Updated trusted host $b%s$b." },
    { "OSMSG_REMOVED_TRUSTED", "Removed trusted hosts from the trusted-hosts list." },
    { "OSMSG_CLONE_EXISTS", "Nick $b%s$b is already in use." },
    { "OSMSG_NOT_A_HOSTMASK", "The hostmask must be in user@host form." },
    { "OSMSG_BADWORD_LIST", "Bad words: %s" },
    { "OSMSG_EXEMPTED_LIST", "Exempted channels: %s" },
    { "OSMSG_GLINE_COUNT", "There are %d glines active on the network." },
    { "OSMSG_SHUN_COUNT", "There are %d shuns active on the network." },
    { "OSMSG_LINKS_SERVER", "%s%s (%u clients; %s)" },
    { "OSMSG_MAX_CLIENTS", "Max clients: %d at %s" },
    { "OSMSG_NETWORK_INFO", "Total users: %d (%d invisible, %d opers)" },
    { "OSMSG_RESERVED_LIST", "List of reserved nicks:" },
    { "OSMSG_TRUSTED_LIST", "$bTrusted Hosts$b" },
    { "OSMSG_TRUSTED_LIST_HEADER", "IP Address      Limit By        Time" },
    { "OSMSG_HOST_IS_TRUSTED",      "%-15s %-5s %-10s set %s ago, expires %s" },
    { "OSMSG_HOST_IS_TRUSTED_DESC", "  Reason: %s" },
    { "OSMSG_TRUSTED_LIST_BAR", "----------------------------------------" },
    { "OSMSG_TRUSTED_LIST_END", "----------End of Trusted Hosts----------" },
    { "OSMSG_HOST_NOT_TRUSTED", "%s does not have a special trust." },
    { "OSMSG_UPTIME_STATS", "Uptime: %s (%u lines processed, CPU time %.2fu/%.2fs)" },
    { "OSMSG_LINE_DUMPED", "Raw line sent." },
    { "OSMSG_RAW_PARSE_ERROR", "Error parsing raw line (not dumping to uplink)." },
    { "OSMSG_COLLIDED_NICK", "Now temporarily holding nick $b%s$b." },
    { "OSMSG_RESERVED_NICK", "Now reserving nick $b%s$b." },
    { "OSMSG_NICK_UNRESERVED", "Nick $b%s$b is no longer reserved." },
    { "OSMSG_NOT_RESERVED", "Nick $b%s$b is not reserved." },
    { "OSMSG_ILLEGAL_REASON", "This channel is illegal." },
    { "OSMSG_ILLEGAL_KILL_REASON", "Joined an illegal modeless channel - do not repeat." },
    { "OSMSG_ILLEGAL_CHANNEL", "$b%s$b is an ILLEGAL channel. Do not re-join it." },
    { "OSMSG_FLOOD_MODERATE", "This channel has been temporarily moderated due to a possible join flood attack detected in this channel; network staff have been notified and will investigate." },
    { "OSMSG_CLONE_WARNING", "WARNING: You have connected the maximum permitted number of clients from one IP address (clones).  If you connect any more, your host will be temporarily banned from the network." },
    { "OSMSG_CLONE_ADDED", "Added clone $b%s$b." },
    { "OSMSG_CLONE_FAILED", "Unable to add user $b%s$b." },
    { "OSMSG_NOT_A_CLONE", "Har har.  $b%s$b isn't a clone." },
    { "OSMSG_CLONE_REMOVED", "Removed clone $b%s$b." },
    { "OSMSG_CLONE_JOINED", "$b%s$b has joined $b%s$b." },
    { "OSMSG_CLONE_PARTED", "$b%s$b has left $b%s$b." },
    { "OSMSG_OPS_GIVEN", "I have given ops in $b%s$b to $b%s$b." },
    { "OSMSG_HOPS_GIVEN", "I have given halfops in $b%s$b to $b%s$b." },
    { "OSMSG_CLONE_SAID", "$b%s$b has spoken to $b%s$b." },
    { "OSMSG_UNKNOWN_SUBCOMMAND", "$b%s$b is not a valid subcommand of $b%s$b." },
    { "OSMSG_UNKNOWN_OPTION", "$b%s$b has not been set." },
    { "OSMSG_OPTION_IS", "$b%s$b is set to $b%s$b." },
    { "OSMSG_OPTION_ROOT", "The following keys can be queried:" },
    { "OSMSG_OPTION_LIST", "$b%s$b contains the following values:" },
    { "OSMSG_OPTION_KEYS", "$b%s$b contains the following keys:" },
    { "OSMSG_OPTION_LIST_EMPTY", "Empty list." },
    { "OSMSG_SET_NOT_SET", "$b%s$b does not exist, and cannot be set." },
    { "OSMSG_SET_BAD_TYPE", "$b%s$b is not a string, and cannot be set." },
    { "OSMSG_SET_SUCCESS", "$b%s$b has been set to $b%s$b." },
    { "OSMSG_SETTIME_SUCCESS", "Set time for servers named like $b%s$b." },
    { "OSMSG_BAD_ACTION", "Unrecognized trace action $b%s$b." },
    { "OSMSG_USER_SEARCH_RESULTS", "The following users were found:" },
    { "OSMSG_USER_SEARCH_HEADER", "Nick                  User@Host   (Account)" },
    { "OSMSG_USER_SEARCH_BAR",    "-------------------------------------------" },
    { "OSMSG_USER_SEARCH_COUNT",  "There were %4u matches" },
    { "OSMSG_USER_SEARCH_COUNT_BAR",  "------------ Found %4u matches -----------" },
    { "OSMSG_MARK_NO_MARK", "MARK action requires mark criteria (what do you want to mark them as?)" },
    { "OSMSG_SVSJOIN_NO_TARGET", "SVSJOIN action requires chantarget criteria (where should they join?)" },
    { "OSMSG_SVSPART_NO_TARGET", "SVSPART action requires chantarget criteria (where should they join?)" },
    { "OSMSG_CHANNEL_SEARCH_RESULTS", "The following channels were found:" },
    { "OSMSG_GLINE_SEARCH_RESULTS", "The following glines were found:" },
    { "OSMSG_SHUN_SEARCH_RESULTS", "The following shun were found:" },
    { "OSMSG_LOG_SEARCH_RESULTS", "The following log entries were found:" },
    { "OSMSG_GSYNC_RUNNING", "Synchronizing glines from %s." },
    { "OSMSG_SSYNC_RUNNING", "Synchronizing shuns from %s." },
    { "OSMSG_GTRACE_FORMAT", "%s (issued %s by %s, expires %s): %s" },
    { "OSMSG_STRACE_FORMAT", "%s (issued %s by %s, expires %s): %s" },
    { "OSMSG_GAG_APPLIED", "Gagged $b%s$b, affecting %d users." },
    { "OSMSG_GAG_ADDED", "Gagged $b%s$b." },
    { "OSMSG_REDUNDANT_GAG", "Gag $b%s$b is redundant." },
    { "OSMSG_GAG_NOT_FOUND", "Could not find gag $b%s$b." },
    { "OSMSG_NO_GAGS", "No gags have been set." },
    { "OSMSG_UNGAG_APPLIED", "Ungagged $b%s$b, affecting %d users." },
    { "OSMSG_UNGAG_ADDED", "Ungagged $b%s$b." },
    { "OSMSG_TIMEQ_INFO", "%u events in timeq; next in %lu seconds." },
    { "OSMSG_ALERT_EXISTS", "An alert named $b%s$b already exists." },
    { "OSMSG_UNKNOWN_REACTION", "Unknown alert reaction $b%s$b." },
    { "OSMSG_ADDED_ALERT", "Added alert named $b%s$b." },
    { "OSMSG_ALERT_ADD_FAILED", "Unable to add alert. Check syntax, required parts,  and access" },
    { "OSMSG_REMOVED_ALERT", "Removed alert named $b%s$b." },
    { "OSMSG_NO_SUCH_ALERT", "No alert named $b%s$b could be found." },
    { "OSMSG_ALERTS_LIST", "$bCurrent $O alerts matching '$b%s$b'$b" },
    { "OSMSG_ALERTS_BAR",    "----------------------------------------------" },
    { "OSMSG_ALERTS_HEADER", "Name                 Action (by Oper)" },
    { "OSMSG_ALERTS_DESC",   "   $uCriteria$u: %s" },
    { "OSMSG_ALERTS_LAST",   "   $uTriggered$u: %s" },
    { "OSMSG_ALERT_IS",      "$b%-20s$b %-6s (by %s)" },
    { "OSMSG_ALERT_END",     "----------------End of Alerts-----------------" },
    /* routing messages */
    { "OSMSG_ROUTINGPLAN",  "$bRouting Plan(s)$b" },
    { "OSMSG_ROUTINGPLAN_LIST_HEAD", "$bRouting Plans$b" },
    { "OSMSG_ROUTINGPLAN_BAR",   "----------------------------------------------" },
    { "OSMSG_ROUTINGPLAN_END",   "------------End of Routing Plan(s)------------" },
    { "OSMSG_ROUTINGPLAN_OPTION", "%s is set to %s" },
    { "OSMSG_ROUTINGPLAN_ACTIVE", "Auto routing is active, using plan '%s'." },
    { "OSMSG_ROUTING_ACTIVATION_ERROR", "There was an error activating the routing plan. Check for loops, and make sure the map includes my own uplink." },
    { "OSMSG_ROUTINGPLAN_OPTION_NOT_FOUND", "There is no routing plan option '%s'." },
    { "OSMSG_ROUTINGPLAN_OPTION_NOT_SET", "Option '%s' is not currently set." },
    { "OSMSG_ROUTINGPLAN_NAME",  "$b%s:$b" },
    { "OSMSG_ROUTINGPLAN_LIST",  "$b%s$b" },
    { "OSMSG_ROUTINGPLAN_SERVER","      %s:%d <-- %s[%d/%s] (%s)" }, 
    { "OSMSG_ADDPLAN_SUCCESS", "Added new routing plan '%s'." },
    { "OSMSG_ADDPLAN_FAILED", "Could not add new plan '%s' (does it already exist?)." },
    { "OSMSG_INVALID_PLAN", "That routing plan name is not valid." },
    { "OSMSG_PLAN_DELETED", "The routing plan was sucessfully deleted." },
    { "OSMSG_PLAN_NOT_FOUND", "There is no routing plan called '%s'." },
    { "OSMSG_PLAN_SERVER_ADDED", "Added %s to the routing plan." },
    { "OSMSG_PLAN_SERVER_DELETED", "The server has been deleted." },
    { "OSMSG_PLAN_SERVER_NOT_FOUND", "The server '%s' was not found in that routing plan." },
    { "OSMSG_ROUTING_DISABLED", "Routing is now disabled." },
    { "OSMSG_DOWNLINKS_FORMAT_A", "%s%s-$b%s$b [%s]" },
    { "OSMSG_DOWNLINKS_FORMAT_B", "$b%s$b (me)" },
    { "OSMSG_ROUTELIST_EMPTY", "No servers in route list" },
    { "OSMSG_ROUTELIST_AS_PLANNED", "Routing plan: Servers as they SHOULD be linked" },
    { "OSMSG_MAP_CENTERED",         "map %s centered, Maxdepth:%d" },
    { "OSMSG_NO_SERVERS_MISSING",   "No servers are missing." },
    { "OSMSG_CONNECTING_MISSING",   "Attempted to connect %d missing servers." },
    { "OSMSG_CONNECT",              "->connect %s %d %s" },
    { "OSMSG_SQUIT",                "->squit %s" },
    { "OSMSG_COULDNT_FIND_SERVER",  "Couldnt find %s, so using %s to link %s" },
    { "OSMSG_INSPECTING_SERVER",    "Inspecting server [%s]" },
    { "OSMSG_REROUTING_ACC_MAP",    "Rerouting network according to loaded map.." },
    { "OSMSG_REROUTING_NOTCONFIGURED", "You have not configured routing. See $/msg $O help routing$b." },
    { "OSMSG_CONNECTING_MISSING_ONLY", "Connecting missing servers only.." },
    { "OSMSG_NO_ROUTING_NECESSARY", "No rerouting appears necessary." },
    { "OSMSG_TESTING_REROUTE",      "Testing Reroute(): Commands not sent to socket.." },
    { "OSMSG_INVALID_DIRECTIVE",    "Reroute(): Invalid directive %s", },
    { "OSMSG_UPLINKS_MISSING",      "%d servers' uplinks were missing, and were not connected." },
    { "OSMSG_REROUTE_COMPLETE",     "Reroute complete: Moved %d, connected %d, total %d changes." },
    /* end of routing */
    { "OSMSG_REHASH_COMPLETE", "Completed rehash of configuration database." },
    { "OSMSG_REHASH_FAILED", "Rehash of configuration database failed, previous configuration is intact." },
    { "OSMSG_REOPEN_COMPLETE", "Closed and reopened all log files." },
    { "OSMSG_RECONNECTING", "Reconnecting to my uplink." },
    { "OSMSG_NUMERIC_COLLIDE", "Numeric %d (%s) is already in use." },
    { "OSMSG_NAME_COLLIDE", "That name is already in use." },
    { "OSMSG_SRV_CREATE_FAILED", "Server creation failed -- check log files." },
    { "OSMSG_SERVER_JUPED", "Added new jupe server %s." },
    { "OSMSG_INVALID_NUMERIC", "Invalid numeric" },
    { "OSMSG_INVALID_SERVERNAME", "Server name must contain a '.'." },
    { "OSMSG_SERVER_NOT_JUPE", "That server is not a juped server." },
    { "OSMSG_SERVER_UNJUPED", "Server jupe removed." },
    /*
    { "OSMSG_WARN_ADDED", "Added channel activity warning for $b%s$b (%s)" },
    { "OSMSG_WARN_EXISTS", "Channel activity warning for $b%s$b already exists." },
    { "OSMSG_WARN_DELETED", "Removed channel activity warning for $b%s$b" },
    { "OSMSG_WARN_NOEXIST", "Channel activity warning for $b%s$b does not exist." },
    { "OSMSG_WARN_LISTSTART", "Channel activity warnings:" },
    { "OSMSG_WARN_LISTENTRY", "%s (%s)" },
    { "OSMSG_WARN_LISTEND", "End of activity warning list." },
    */
    { "OSMSG_UPLINK_CONNECTING", "Establishing connection with %s (%s:%d)." },
    { "OSMSG_CURRENT_UPLINK", "$b%s$b is already the current uplink." },
    { "OSMSG_INVALID_UPLINK", "$b%s$b is not a valid uplink name." },
    { "OSMSG_UPLINK_DISABLED", "$b%s$b is a disabled or unavailable uplink." },
    { "OSMSG_UPLINK_START", "Uplink $b%s$b:" },
    { "OSMSG_UPLINK_ADDRESS", "Address: %s:%d" },
    { "OSMSG_STUPID_GLINE", "Gline %s?  Now $bthat$b would be smooth." },
    { "OSMSG_STUPID_SHUN", "Shun %s?  Now $bthat$b would be smooth." },
    { "OSMSG_ACCOUNTMASK_AUTHED", "Invalid criteria: it is impossible to match an account mask but not be authed" },
    { "OSMSG_CHANINFO_HEADER", "%s Information" },
    { "OSMSG_CHANINFO_TIMESTAMP", "Created on: %a %b %d %H:%M:%S %Y (%s)" },
    { "OSMSG_CHANINFO_MODES", "Modes: %s" },
    { "OSMSG_CHANINFO_MODES_BADWORD", "Modes: %s; bad-word channel" },
    { "OSMSG_CHANINFO_TOPIC", "Topic (set by %%s, %a %b %d %H:%M:%S %Y): %%s" },
    { "OSMSG_CHANINFO_TOPIC_UNKNOWN", "Topic: (none / not gathered)" },
    { "OSMSG_CHANINFO_BAN_COUNT", "Bans (%d):" },
    { "OSMSG_CHANINFO_BAN", "%%s by %%s (%a %b %d %H:%M:%S %Y)" },
    { "OSMSG_CHANINFO_EXEMPT_COUNT", "Exempts (%d):" },
    { "OSMSG_CHANINFO_EXEMPT", "%%s by %%s (%a %b %d %H:%M:%S %Y)" },
    { "OSMSG_CHANINFO_MANY_USERS", "%d users (\"/msg $S %s %s users\" for the list)" },
    { "OSMSG_CHANINFO_USER_COUNT", "Users (%d):" },
    { "OSMSG_CSEARCH_CHANNEL_INFO", "%s [%d users] %s %s" },
    { "OSMSG_INVALID_REGEX", "Invalid regex: %s: %s (%d)" },
    { "OSMSG_TRACK_DISABLED", "Tracking is not currently compiled into X3" },
    { "OSMSG_MAXUSERS_RESET", "Max clients has been reset to $b%d$b" },

    { "OSMSG_DEFCON_INVALID", "DefCon level %d is invalid, please choose a value between 1 and 5" },
    { "OSMSG_DEFCON_ALLOWING_ALL", "DefCon is at level 5 and allowing everything" },
    { "OSMSG_DEFCON_DISALLOWING", "DefCon is at level %d and enforcing:" },
    { "OSMSG_DEFCON_NO_NEW_CHANNELS", "No Channel Registrations" },
    { "OSMSG_DEFCON_NO_NEW_NICKS", "No Nickname/Account Registrations" },
    { "OSMSG_DEFCON_NO_MODE_CHANGE", "No Channel Mode Changes" },
    { "OSMSG_DEFCON_NO_NEW_CLIENTS", "No New Clients" },
    { "OSMSG_DEFCON_FORCE_CHANMODES", "Forcing Channel Mode(s): %s" },
    { "OSMSG_DEFCON_REDUCE_SESSION", "Forcing Reduced Session: %d" },
    { "OSMSG_DEFCON_OPER_ONLY", "Allowing Services Communication With Opers Only" },
    { "OSMSG_DEFCON_SILENT_OPER_ONLY", "Allowing Services Communication With Opers Only AND Silently Ignoring Regular Users" },
    { "OSMSG_DEFCON_GLINE_NEW_CLIENTS", "Glining New Clients" },
    { "OSMSG_DEFCON_SHUN_NEW_CLIENTS", "Shunning New Clients" },
    { "OSMSG_DEFCON_NO_NEW_MEMOS", "Disallowing New Memos" },

    { "OSMSG_PRIV_UNKNOWN", "Unknown privilege flag %s, see /msg $O HELP PRIVFLAGS for a flag list" },
    { "OSMSG_PRIV_SET",     "Privilege flag %s has been %sset" },

    { NULL, NULL }
};

#define OPSERV_SYNTAX() svccmd_send_help_brief(user, opserv, cmd)

int DefConLevel = 5;
int DefCon[6];
int DefConTimeOut;
int GlobalOnDefcon = 0;
int GlobalOnDefconMore = 0;
int DefConGlineExpire;
int DefConModesSet = 0;
unsigned int DefConSessionLimit;
char *DefConChanModes;
char *DefConGlineReason;
char *DefConMessage;
char *DefConOffMessage;

extern void add_track_user(struct userNode *user);
typedef int (*discrim_search_func)(struct userNode *match, void *extra);

struct userNode *opserv;
static struct service *opserv_service;

/*static dict_t opserv_chan_warn; */ /* data is char* */
static dict_t opserv_reserved_nick_dict; /* data is struct userNode* */
static struct string_list *opserv_bad_words;
static dict_t opserv_exempt_channels; /* data is not used */
static dict_t opserv_trusted_hosts; /* data is struct trusted_host* */
static dict_t opserv_routing_plans; /* data is struct routingPlan */
static dict_t opserv_routing_plan_options; /* data is a dict_t key->val list*/
static dict_t opserv_waiting_connections; /* data is struct waitingConnection */
static dict_t opserv_hostinfo_dict; /* data is struct opserv_hostinfo* */
static dict_t opserv_user_alerts; /* data is struct opserv_user_alert* */
static dict_t opserv_nick_based_alerts; /* data is struct opserv_user_alert* */
static dict_t opserv_channel_alerts; /* data is struct opserv_user_alert* */
static struct module *opserv_module;
static struct log_type *OS_LOG;
static unsigned int new_user_flood;
static char *level_strings[1001];
struct string_list *autojoin_channels;
struct route *opserv_route = NULL; /* Main active routing table from activate_routing()*/

static struct {
    struct chanNode *debug_channel;
    struct chanNode *alert_channel;
    struct chanNode *staff_auth_channel;
    struct policer_params *join_policer_params;
    struct policer new_user_policer;
    unsigned long untrusted_max;
    unsigned long clone_gline_duration;
    unsigned long block_gline_duration;
    unsigned long block_shun_duration;
    unsigned long purge_lock_delay;
    unsigned long join_flood_moderate;
    unsigned long join_flood_moderate_threshold;
    unsigned long admin_level;
    unsigned long silent_level;
} opserv_conf;

struct trusted_host {
    char *ipaddr;
    char *issuer;
    char *reason;
    unsigned long limit;
    time_t issued;
    time_t expires;
};

struct gag_entry {
    char *mask;
    char *owner;
    char *reason;
    time_t expires;
    struct gag_entry *next;
};

static struct gag_entry *gagList;

struct opserv_hostinfo {
    struct userList clients;
    struct trusted_host *trusted;
};

static void
opserv_free_hostinfo(void *data)
{
    struct opserv_hostinfo *ohi = data;
    userList_clean(&ohi->clients);
    free(ohi);
}

static void
opserv_free_waiting_connection(void *data)
{
    struct waitingConnection *wc = data;
    free(wc->server);
    free(wc->target);
    free(wc);
}

typedef struct opservDiscrim {
    struct chanNode *channel;
    char *mask_nick, *mask_ident, *mask_host, *mask_info, *mask_version, *server, *reason, *accountmask, *chantarget, *mark, *mask_mark, *modes;
    irc_in_addr_t ip_mask;
    unsigned long limit;
    time_t min_ts, max_ts;
    regex_t regex_nick, regex_ident, regex_host, regex_info, regex_version;
    unsigned int has_regex_nick : 1, has_regex_ident : 1, has_regex_host : 1, has_regex_info : 1, has_regex_version : 1;
    unsigned int min_level, max_level, domain_depth, duration, min_clones, min_channels, max_channels;
    unsigned char ip_mask_bits;
    unsigned int match_opers : 1, option_log : 1;
    unsigned int chan_req_modes : 2, chan_no_modes : 2;
    int authed : 2, info_space : 2;
    unsigned int intra_scmp : 2, intra_dcmp : 2;
    unsigned int use_regex : 1;
    unsigned int silent : 1;
    unsigned int checkrestrictions : 2;
} *discrim_t;

struct discrim_and_source {
    discrim_t discrim;
    struct userNode *source;
    struct userNode *destination;
    dict_t dict;
    unsigned int disp_limit;
};

static discrim_t opserv_discrim_create(struct userNode *user, struct userNode *bot, unsigned int argc, char *argv[], int allow_channel);
static unsigned int opserv_discrim_search(discrim_t discrim, discrim_search_func dsf, void *data);
static int gag_helper_func(struct userNode *match, void *extra);
static int ungag_helper_func(struct userNode *match, void *extra);

typedef enum {
    REACT_NOTICE,
    REACT_KILL,
    REACT_GLINE,
    REACT_TRACK,
    REACT_SHUN,
    REACT_SVSJOIN,
    REACT_SVSPART,
    REACT_VERSION,
    REACT_MARK
} opserv_alert_reaction;

struct opserv_user_alert {
    char *owner;
    char *text_discrim, *split_discrim;
    discrim_t discrim;
    opserv_alert_reaction reaction;
    int last;
};

/* funny type to make it acceptible to dict_set_free_data, far below */
static void
opserv_free_user_alert(void *data)
{
    struct opserv_user_alert *alert = data;
    if (alert->discrim->channel)
        UnlockChannel(alert->discrim->channel);
    free(alert->owner);
    free(alert->text_discrim);
    free(alert->split_discrim);
    if(alert->discrim->has_regex_nick)
      regfree(&alert->discrim->regex_nick);
    if(alert->discrim->has_regex_ident)
      regfree(&alert->discrim->regex_ident);
    if(alert->discrim->has_regex_host)
      regfree(&alert->discrim->regex_host);
    if(alert->discrim->has_regex_info)
      regfree(&alert->discrim->regex_info);
    if(alert->discrim->has_regex_version)
      regfree(&alert->discrim->regex_version);
    free(alert->discrim->reason);
    free(alert->discrim);
    free(alert);
}

#define opserv_debug(format...) do { if (opserv_conf.debug_channel) send_channel_notice(opserv_conf.debug_channel , opserv , ## format); } while (0)
#define opserv_alert(format...) do { if (opserv_conf.alert_channel) send_channel_notice(opserv_conf.alert_channel , opserv , ## format); } while (0)


char *defconReverseModes(const char *modes)
{
    char *newmodes = NULL;
    unsigned int i = 0;
    if (!modes) {
        return NULL;
    }
    if (!(newmodes = malloc(sizeof(char) * strlen(modes) + 1))) {
        return NULL;
    }
    for (i = 0; i < strlen(modes); i++) {
        if (modes[i] == '+')
            newmodes[i] = '-';
        else if (modes[i] == '-')
            newmodes[i] = '+';
        else
            newmodes[i] = modes[i];
    }
    newmodes[i] = '\0';
    return newmodes;
}

int checkDefCon(int level)
{
    return DefCon[DefConLevel] & level;
}

void showDefConSettings(struct userNode *user, struct svccmd *cmd)
{
    if (DefConLevel == 5) {
        reply("OSMSG_DEFCON_ALLOWING_ALL");
        return;
    } else
        reply("OSMSG_DEFCON_DISALLOWING", DefConLevel);

    if (checkDefCon(DEFCON_NO_NEW_CHANNELS))
        reply("OSMSG_DEFCON_NO_NEW_CHANNELS");

    if (checkDefCon(DEFCON_NO_NEW_NICKS))
        reply("OSMSG_DEFCON_NO_NEW_NICKS");

    if (checkDefCon(DEFCON_NO_MODE_CHANGE))
        reply("OSMSG_DEFCON_NO_MODE_CHANGE");

    if (checkDefCon(DEFCON_FORCE_CHAN_MODES) && (DefConChanModes))
        reply("OSMSG_DEFCON_FORCE_CHANMODES", DefConChanModes);

    if (checkDefCon(DEFCON_REDUCE_SESSION))
        reply("OSMSG_DEFCON_REDUCE_SESSION", DefConSessionLimit);

    if (checkDefCon(DEFCON_NO_NEW_CLIENTS))
        reply("OSMSG_DEFCON_NO_NEW_CLIENTS");

    if (checkDefCon(DEFCON_OPER_ONLY))
        reply("OSMSG_DEFCON_OPER_ONLY");

    if (checkDefCon(DEFCON_SILENT_OPER_ONLY))
        reply("OSMSG_DEFCON_SILENT_OPER_ONLY");

    if (checkDefCon(DEFCON_GLINE_NEW_CLIENTS))
        reply("OSMSG_DEFCON_GLINE_NEW_CLIENTS");

    if (checkDefCon(DEFCON_SHUN_NEW_CLIENTS))
        reply("OSMSG_DEFCON_SHUN_NEW_CLIENTS");

    if (checkDefCon(DEFCON_NO_NEW_MEMOS))
        reply("OSMSG_DEFCON_NO_NEW_MEMOS");

    return;
}

void do_mass_mode(char *modes)
{
    dict_iterator_t it;

    if (!modes)
        return;

    for (it = dict_first(channels); it; it = iter_next(it)) {
        struct chanNode *chan = iter_data(it);

        irc_mode(opserv, chan, modes);
    }

}

void DefConProcess(struct userNode *user)
{
    char *newmodes;

    if (GlobalOnDefcon)
        global_message_args(MESSAGE_RECIPIENT_LUSERS, "DEFCON_NETWORK_CHANGED", DefConLevel);

    if (GlobalOnDefconMore && GlobalOnDefcon)
        global_message(MESSAGE_RECIPIENT_LUSERS, DefConMessage);

    if ((DefConLevel == 5) && !GlobalOnDefconMore && !GlobalOnDefcon)
        global_message(MESSAGE_RECIPIENT_LUSERS, DefConOffMessage);

    if (user)
       global_message_args(MESSAGE_RECIPIENT_OPERS, "DEFCON_OPER_LEVEL_CHANGE", user->nick, DefConLevel);
    else
       global_message_args(MESSAGE_RECIPIENT_OPERS, "DEFCON_TIMEOUT_LEVEL_CHANGE", DefConLevel);

    if (checkDefCon(DEFCON_FORCE_CHAN_MODES)) {
        if (DefConChanModes && !DefConModesSet) {
            if (DefConChanModes[0] == '+' || DefConChanModes[0] == '-') {
                do_mass_mode(DefConChanModes);
                DefConModesSet = 1;
            }
        }
    } else {
        if (DefConChanModes && (DefConModesSet != 0)) {
            if (DefConChanModes[0] == '+' || DefConChanModes[0] == '-') {
                if ((newmodes = defconReverseModes(DefConChanModes))) {
                    do_mass_mode(newmodes);
                    free(newmodes);
                }
                DefConModesSet = 0;
            }
        }
    }

    return;
}

void
defcon_timeout(UNUSED_ARG(void *data))
{
    DefConLevel = 5;
    DefConProcess(NULL);
}

static MODCMD_FUNC(cmd_defcon)
{
    if ((argc < 2) || (atoi(argv[1]) == DefConLevel)) {
        showDefConSettings(user, cmd);
        return 1;
    }

    if ((atoi(argv[1]) < 1) || (atoi(argv[1]) > 5)) {
        reply("OSMSG_DEFCON_INVALID", atoi(argv[1]));
        return 0;
    }

    DefConLevel = atoi(argv[1]);
    showDefConSettings(user, cmd);

    if (DefConTimeOut > 0) {
        timeq_del(0, defcon_timeout, NULL, TIMEQ_IGNORE_DATA | TIMEQ_IGNORE_WHEN);
        timeq_add(now + DefConTimeOut, defcon_timeout, NULL);
    }

    DefConProcess(user);
    return 1;
}

/* TODO
static MODCMD_FUNC(cmd_privallow)
{
//privallow servername/username +/-flag (global is set in conf)
}

static MODCMD_FUNC(cmd_privdissallow)
{
//privdisallow servername/username +/-flag (global is set in conf)
}

static MODCMD_FUNC(cmd_privlist)
{
//privlist servername/user (global with none)
}
*/

static MODCMD_FUNC(cmd_privset)
{
    struct userNode *target;
    char *flag;
    int add = PRIV_ADD;

    flag = argv[2];
    if (*flag == '-') {
        add = PRIV_DEL;
        flag++;    
    } else if (*flag == '+') {
        add = PRIV_ADD;
        flag++;
    }

    target = GetUserH(argv[1]);
    if (!target) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }

    if (check_priv(flag)) {
        irc_privs(target, flag, add);
        reply("OSMSG_PRIV_SET", argv[2], (add == 1) ? "" : "un");
    } else {
        reply("OSMSG_PRIV_UNKNOWN", argv[2]);
        return 0;
    }

    return 1;
}

/* A lot of these commands are very similar to what ChanServ can do,
 * but OpServ can do them even on channels that aren't registered.
 */

static MODCMD_FUNC(cmd_access)
{
    struct handle_info *hi;
    const char *target;
    unsigned int res;

    target = (argc > 1) ? (const char*)argv[1] : user->nick;
    if (!irccasecmp(target, "*")) {
        nickserv_show_oper_accounts(user, cmd);
        return 1;
    }
    if (!(hi = modcmd_get_handle_info(user, target)))
        return 0;
    res = (argc > 2) ? oper_try_set_access(user, opserv_service->bot, hi, strtoul(argv[2], NULL, 0)) : 0;
    reply("OSMSG_USER_ACCESS_IS", target, hi->handle, hi->opserv_level);
    return res;
}

static MODCMD_FUNC(cmd_ban)
{
    struct mod_chanmode change;
    struct userNode *victim;

    mod_chanmode_init(&change);
    change.argc = 1;
    change.args[0].mode = MODE_BAN;
    if (is_ircmask(argv[1]))
        change.args[0].u.hostmask = strdup(argv[1]);
    else if ((victim = GetUserH(argv[1])))
        change.args[0].u.hostmask = generate_hostmask(victim, 0);
    else {
        reply("OSMSG_INVALID_IRCMASK", argv[1]);
        return 0;
    }
    modcmd_chanmode_announce(&change);
    reply("OSMSG_ADDED_BAN", change.args[0].u.hostmask, channel->name);
    free((char*)change.args[0].u.hostmask);
    return 1;
}

static MODCMD_FUNC(cmd_chaninfo)
{
    char buffer[MAXLEN];
    const char *fmt;
    struct banNode *ban;
    struct exemptNode *exempt;
    struct modeNode *moden;
    unsigned int n;

    reply("OSMSG_CHANINFO_HEADER", channel->name);
    fmt = user_find_message(user, "OSMSG_CHANINFO_TIMESTAMP");
    strftime(buffer, sizeof(buffer), fmt, gmtime(&channel->timestamp));
    send_message_type(4, user, cmd->parent->bot, "%s", buffer);
    irc_make_chanmode(channel, buffer);
    if (channel->bad_channel)
        reply("OSMSG_CHANINFO_MODES_BADWORD", buffer);
    else
        reply("OSMSG_CHANINFO_MODES", buffer);
    if (channel->topic_time) {
        fmt = user_find_message(user, "OSMSG_CHANINFO_TOPIC");
        strftime(buffer, sizeof(buffer), fmt, gmtime(&channel->topic_time));
        send_message_type(4, user, cmd->parent->bot, buffer, channel->topic_nick, channel->topic);
    } else {
        irc_fetchtopic(cmd->parent->bot, channel->name);
        reply("OSMSG_CHANINFO_TOPIC_UNKNOWN");
    }
    if (channel->banlist.used) {
        reply("OSMSG_CHANINFO_BAN_COUNT", channel->banlist.used);
        fmt = user_find_message(user, "OSMSG_CHANINFO_BAN");
        for (n = 0; n < channel->banlist.used; n++) {
            ban = channel->banlist.list[n];
            strftime(buffer, sizeof(buffer), fmt, localtime(&ban->set));
            send_message_type(4, user, cmd->parent->bot, buffer, ban->ban, ban->who);
        }
    }
    if (channel->exemptlist.used) {
        reply("OSMSG_CHANINFO_EXEMPT_COUNT", channel->exemptlist.used);
        fmt = user_find_message(user, "OSMSG_CHANINFO_EXEMPT");
        for (n = 0; n < channel->exemptlist.used; n++) {
            exempt = channel->exemptlist.list[n];
            strftime(buffer, sizeof(buffer), fmt, localtime(&exempt->set));
            send_message_type(4, user, cmd->parent->bot, buffer, exempt->exempt, exempt->who);
        }
    }
    if ((argc < 2) && (channel->members.used >= 50)) {
        /* early out unless they ask for users */
        reply("OSMSG_CHANINFO_MANY_USERS", channel->members.used, argv[0], channel->name);
        return 1;
    }
    reply("OSMSG_CHANINFO_USER_COUNT", channel->members.used);
    for (n=0; n<channel->members.used; n++) {
        moden = channel->members.list[n];
        if (moden->modes & MODE_CHANOP) {
            if (moden->oplevel >= 0)
                 send_message_type(4, user, cmd->parent->bot, " @%s:%d (%s@%s)", moden->user->nick, moden->oplevel, moden->user->ident, moden->user->hostname);
            else
                 send_message_type(4, user, cmd->parent->bot, " @%s (%s@%s)", moden->user->nick, moden->user->ident, moden->user->hostname);
        }
    }
    for (n=0; n<channel->members.used; n++) {
        moden = channel->members.list[n];
        if ((moden->modes & (MODE_CHANOP|MODE_HALFOP|MODE_VOICE)) == MODE_HALFOP)
            send_message_type(4, user, cmd->parent->bot, " %s%s (%s@%s)", "%", moden->user->nick, moden->user->ident, moden->user->hostname);
    }
    for (n=0; n<channel->members.used; n++) {
        moden = channel->members.list[n];
        if ((moden->modes & (MODE_CHANOP|MODE_HALFOP|MODE_VOICE)) == MODE_VOICE)
            send_message_type(4, user, cmd->parent->bot, " +%s (%s@%s)", moden->user->nick, moden->user->ident, moden->user->hostname);
    }
    for (n=0; n<channel->members.used; n++) {
        moden = channel->members.list[n];
        if ((moden->modes & (MODE_CHANOP|MODE_HALFOP|MODE_VOICE)) == 0)
            send_message_type(4, user, cmd->parent->bot, "  %s (%s@%s)", moden->user->nick, moden->user->ident, moden->user->hostname);
    }
    return 1;
}

/* This command has been replaced by 'alert notice channel #foo' */
/*
static MODCMD_FUNC(cmd_warn)
{
    char *reason, *message;

    if (!IsChannelName(argv[1])) {
        reply("OSMSG_NEED_CHANNEL", argv[0]);
        return 0;
    }
    reason = dict_find(opserv_chan_warn, argv[1], NULL);
    if (reason) {
        reply("OSMSG_WARN_EXISTS", argv[1]);
        return 0;
    }
    if (argv[2])
        reason = strdup(unsplit_string(argv+2, argc-2, NULL));
    else
        reason = strdup("No reason");
    dict_insert(opserv_chan_warn, strdup(argv[1]), reason);
    reply("OSMSG_WARN_ADDED", argv[1], reason);
    if (dict_find(channels, argv[1], NULL)) {
        global_message_args(MESSAGE_RECIPIENT_OPERS, "OSMSG_CHANNEL_ACTIVITY_WARN" argv[1], reason);
    }
    return 1;
}

static MODCMD_FUNC(cmd_unwarn)
{
    if ((argc < 2) || !IsChannelName(argv[1])) {
        reply("OSMSG_NEED_CHANNEL", argv[0]);
        return 0;
    }
    if (!dict_remove(opserv_chan_warn, argv[1])) {
        reply("OSMSG_WARN_NOEXIST", argv[1]);
        return 0;
    }
    reply("OSMSG_WARN_DELETED", argv[1]);
    return 1;
}
*/

static MODCMD_FUNC(cmd_clearbans)
{
    struct mod_chanmode *change;
    unsigned int ii;

    change = mod_chanmode_alloc(channel->banlist.used);
    for (ii=0; ii<channel->banlist.used; ii++) {
        change->args[ii].mode = MODE_REMOVE | MODE_BAN;
        change->args[ii].u.hostmask = strdup(channel->banlist.list[ii]->ban);
    }
    modcmd_chanmode_announce(change);
    for (ii=0; ii<change->argc; ++ii)
        free((char*)change->args[ii].u.hostmask);
    mod_chanmode_free(change);
    reply("OSMSG_CLEARBANS_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_clearmodes)
{
    struct mod_chanmode change;

    if (!channel->modes) {
        reply("OSMSG_NO_CHANNEL_MODES", channel->name);
        return 0;
    }
    mod_chanmode_init(&change);
    change.modes_clear = channel->modes;
    modcmd_chanmode_announce(&change);
    reply("OSMSG_CLEARMODES_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_deop)
{
    struct mod_chanmode *change;
    unsigned int arg, count;

    change = mod_chanmode_alloc(argc-1);
    for (arg = 1, count = 0; arg < argc; ++arg) {
        struct userNode *victim = GetUserH(argv[arg]);
        struct modeNode *mn;
        if (!victim || IsService(victim)
            || !(mn = GetUserMode(channel, victim))
            || !(mn->modes & MODE_CHANOP))
            continue;
        change->args[count].mode = MODE_REMOVE | MODE_CHANOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_DEOP_DONE");
    return 1;
}

static MODCMD_FUNC(cmd_dehop)
{
    struct mod_chanmode *change;
    unsigned int arg, count;

    change = mod_chanmode_alloc(argc-1);
    for (arg = 1, count = 0; arg < argc; ++arg) {
        struct userNode *victim = GetUserH(argv[arg]);
        struct modeNode *mn;
        if (!victim || IsService(victim)
            || !(mn = GetUserMode(channel, victim))
            || !(mn->modes & MODE_HALFOP))
            continue;
        change->args[count].mode = MODE_REMOVE | MODE_HALFOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_DEHOP_DONE");
    return 1;
}

static MODCMD_FUNC(cmd_deopall)
{
    struct mod_chanmode *change;
    unsigned int ii, count;

    change = mod_chanmode_alloc(channel->members.used);
    for (ii = count = 0; ii < channel->members.used; ++ii) {
        struct modeNode *mn = channel->members.list[ii];
        if (IsService(mn->user) || !(mn->modes & MODE_CHANOP))
            continue;
        change->args[count].mode = MODE_REMOVE | MODE_CHANOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_DEOPALL_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_dehopall)
{
    struct mod_chanmode *change;
    unsigned int ii, count;

    change = mod_chanmode_alloc(channel->members.used);
    for (ii = count = 0; ii < channel->members.used; ++ii) {
        struct modeNode *mn = channel->members.list[ii];
        if (IsService(mn->user) || !(mn->modes & MODE_HALFOP))
            continue;
        change->args[count].mode = MODE_REMOVE | MODE_HALFOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_DEHOPALL_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_resetmax)
{
    max_clients = dict_size(clients);
    max_clients_time = now;
    reply("OSMSG_MAXUSERS_RESET", max_clients);
    return 1;
}

static MODCMD_FUNC(cmd_rehash)
{
    extern char *services_config;

    if (conf_read(services_config))
        reply("OSMSG_REHASH_COMPLETE");
    else
        reply("OSMSG_REHASH_FAILED");
    return 1;
}

static MODCMD_FUNC(cmd_reopen)
{
    log_reopen();
    reply("OSMSG_REOPEN_COMPLETE");
    return 1;
}

static MODCMD_FUNC(cmd_reconnect)
{
    reply("OSMSG_RECONNECTING");
    irc_squit(self, "Reconnecting.", NULL);
    return 1;
}

static MODCMD_FUNC(cmd_jupe)
{
    extern int force_n2k;
    struct server *newsrv;
    unsigned int num;
    char numeric[COMBO_NUMERIC_LEN+1], srvdesc[SERVERDESCRIPTMAX+1];

    num = atoi(argv[2]);
    if(num == 0) {
        reply("OSMSG_INVALID_NUMERIC");
        return 0;
    }
    if ((num < 64) && !force_n2k) {
        inttobase64(numeric, num, 1);
        inttobase64(numeric+1, 64*64-1, 2);
    } else {
        inttobase64(numeric, num, 2);
        inttobase64(numeric+2, 64*64*64-1, 3);
    }
#ifdef WITH_PROTOCOL_P10
    if (GetServerN(numeric)) {
        reply("OSMSG_NUMERIC_COLLIDE", num, numeric);
        return 0;
    }
#endif
    if (GetServerH(argv[1])) {
        reply("OSMSG_NAME_COLLIDE");
        return 0;
    }
    snprintf(srvdesc, sizeof(srvdesc), "JUPE %s", unsplit_string(argv+3, argc-3, NULL));
    if(!strchr(argv[1], '.')) {
        reply("OSMSG_INVALID_SERVERNAME");
        return 0;
    }
    newsrv = AddServer(self, argv[1], 1, now, now, numeric, srvdesc);
    if (!newsrv) {
        reply("OSMSG_SRV_CREATE_FAILED");
        return 0;
    }
    irc_server(newsrv);
    reply("OSMSG_SERVER_JUPED", argv[1]);
    return 1;
}

static MODCMD_FUNC(cmd_unjupe)
{
    struct server *srv;
    char *reason;

    srv = GetServerH(argv[1]);
    if (!srv) {
        reply("MSG_SERVER_UNKNOWN", argv[1]);
        return 0;
    }
    if (strncmp(srv->description, "JUPE", 4)) {
        reply("OSMSG_SERVER_NOT_JUPE");
        return 0;
    }
    reason = (argc > 2) ? unsplit_string(argv+2, argc-2, NULL) : "Unjuping server";
    DelServer(srv, 1, reason);
    reply("OSMSG_SERVER_UNJUPED");
    return 1;
}

static MODCMD_FUNC(cmd_jump)
{
    extern struct cManagerNode cManager;
    void uplink_select(char *name);
    struct uplinkNode *uplink_find(char *name);
    struct uplinkNode *uplink;
    char *target;

    target = unsplit_string(argv+1, argc-1, NULL);

    if (!strcmp(cManager.uplink->name, target)) {
        reply("OSMSG_CURRENT_UPLINK", cManager.uplink->name);
        return 0;
    }

    uplink = uplink_find(target);
    if (!uplink) {
        reply("OSMSG_INVALID_UPLINK", target);
        return 0;
    }
    if (uplink->flags & UPLINK_UNAVAILABLE) {
        reply("OSMSG_UPLINK_DISABLED", uplink->name);
        return 0;
    }

    reply("OSMSG_UPLINK_CONNECTING", uplink->name, uplink->host, uplink->port);
    uplink_select(target);
    irc_squit(self, "Reconnecting.", NULL);
    return 1;
}

static MODCMD_FUNC(cmd_die)
{
    char *reason, *text;

    text = unsplit_string(argv+1, argc-1, NULL);
    reason = alloca(strlen(text) + strlen(user->nick) + 20);
    sprintf(reason, "Disconnected by %s [%s]", user->nick, text);
    irc_squit(self, reason, text);
    quit_services = 1;
    return 1;
}

static MODCMD_FUNC(cmd_restart)
{
    extern int services_argc;
    extern char **services_argv;
    char **restart_argv, *reason, *text;

    text = unsplit_string(argv+1, argc-1, NULL);
    reason = alloca(strlen(text) + strlen(user->nick) + 17);
    sprintf(reason, "Restarted by %s [%s]", user->nick, text);
    irc_squit(self, reason, text);

    /* Append a NULL to the end of argv[]. */
    restart_argv = (char **)alloca((services_argc + 1) * sizeof(char *));
    memcpy(restart_argv, services_argv, services_argc * sizeof(char *));
    restart_argv[services_argc] = NULL;

    call_exit_funcs();

    /* Don't blink. */
    execv(services_argv[0], restart_argv);

    /* If we're still here, that means something went wrong. Reconnect. */
    return 1;
}

static struct gline *
opserv_block(struct userNode *target, char *src_handle, char *reason, unsigned long duration, int silent)
{
    char mask[IRC_NTOP_MAX_SIZE+3] = { '*', '@', '\0' };
    irc_ntop(mask + 2, sizeof(mask) - 2, &target->ip);
    if (!reason)
        snprintf(reason = alloca(MAXLEN), MAXLEN,
                 "G-line requested by %s.", src_handle);
    if (!duration)
        duration = opserv_conf.block_gline_duration;
    return gline_add(src_handle, mask, duration, reason, now, 1, silent ? 1 : 0);
}

static MODCMD_FUNC(cmd_block)
{
    struct userNode *target;
    struct gline *gline;
    char *reason;

    target = GetUserH(argv[1]);
    if (!target) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    if (IsService(target)) {
        reply("MSG_SERVICE_IMMUNE", target->nick);
        return 0;
    }
    reason = (argc > 2) ? unsplit_string(argv+2, argc-2, NULL) : NULL;
    gline = opserv_block(target, user->handle_info->handle, reason, 0, 0);
    reply("OSMSG_GLINE_ISSUED", gline->target);
    return 1;
}

static MODCMD_FUNC(cmd_gline)
{
    unsigned long duration;
    char *reason;
    struct gline *gline;

    reason = unsplit_string(argv+3, argc-3, NULL);
    if (!is_gline(argv[1]) && !IsChannelName(argv[1]) && (argv[1][0] != '&')) {
        reply("MSG_INVALID_GLINE", argv[1]);
        return 0;
    }
    if (!argv[1][strspn(argv[1], "#&*?@.")] && (strlen(argv[1]) < 10)) {
        reply("OSMSG_STUPID_GLINE", argv[1]);
        return 0;
    }
    duration = ParseInterval(argv[2]);
    if (!duration) {
        reply("MSG_INVALID_DURATION", argv[2]);
        return 0;
    }
    gline = gline_add(user->handle_info->handle, argv[1], duration, reason, now, 1, 0);
    reply("OSMSG_GLINE_ISSUED", gline->target);
    return 1;
}

static MODCMD_FUNC(cmd_ungline)
{
    if (gline_remove(argv[1], 1))
        reply("OSMSG_GLINE_REMOVED", argv[1]);
    else
        reply("OSMSG_GLINE_FORCE_REMOVED", argv[1]);
    return 1;
}

static MODCMD_FUNC(cmd_refreshg)
{
    if (argc > 1) {
        unsigned int count;
        dict_iterator_t it;
        struct server *srv;

        for (it=dict_first(servers), count=0; it; it=iter_next(it)) {
            srv = iter_data(it);
            if ((srv == self) || !match_ircglob(srv->name, argv[1]))
                continue;
            gline_refresh_server(srv);
            reply("OSMSG_GLINES_ONE_REFRESHED", srv->name);
            count++;
        }
        if (!count) {
            reply("MSG_SERVER_UNKNOWN", argv[1]);
            return 0;
        }
    } else {
        gline_refresh_all();
        reply("OSMSG_GLINES_REFRESHED");
    }
    return 1;
}

static void
opserv_version(struct userNode *target)
{
    irc_version_user(opserv, target);
}

static void
opserv_mark(struct userNode *target, UNUSED_ARG(char *src_handle), UNUSED_ARG(char *reason), char *mark)
{
    if(!mark)
        return;
    irc_mark(target, mark);
}

static void
opserv_svsjoin(struct userNode *target, UNUSED_ARG(char *src_handle), UNUSED_ARG(char *reason), char *channame, unsigned int checkrestrictions)
{
    struct chanNode *channel;

    if(!channame || !IsChannelName(channame)) {
        /* Not a valid channel name. We shouldnt ever get this if we check properly in addalert */
       return;
    }

    if (!(channel = GetChannel(channame))) {
       channel = AddChannel(channame, now, NULL, NULL, NULL);
    }
    if (GetUserMode(channel, target)) {
        /* already in it */
        return;
    }

    if (checkrestrictions) {
        if (trace_check_bans(target, channel) == 1) {
            return; /* found on lamer list */
        }

        if (channel->modes & MODE_INVITEONLY) {
            return; /* channel is invite only */
        }

        if (channel->limit > 0) {
            if (channel->members.used >= channel->limit) {
                return; /* channel is invite on */
            }
        }

        if (*channel->key) {
            return; /* channel is password protected */
        }
    }

    irc_svsjoin(opserv, target, channel);
    /* Should we tell the user they got joined? -Rubin*/
}

static void
opserv_svspart(struct userNode *target, UNUSED_ARG(char *src_handle), UNUSED_ARG(char *reason), char *channame)
{
    struct chanNode *channel;

    if(!channame || !IsChannelName(channame)) {
        /* Not a valid channel name. We shouldnt ever get this if we check properly in addalert */
       return;
    }

    if (!(channel = GetChannel(channame))) {
       /* channel doesnt exist */
       return;
    }

    if (!GetUserMode(channel, target)) {
        /* not in it */
        return;
    }

    irc_svspart(opserv, target, channel);
}

static struct shun *
opserv_shun(struct userNode *target, char *src_handle, char *reason, unsigned long duration)
{
    char *mask;
    mask = alloca(MAXLEN);
    snprintf(mask, MAXLEN, "*@%s", target->hostname);
    if (!reason) {
        reason = alloca(MAXLEN);
        snprintf(reason, MAXLEN, "Shun requested by %s.", src_handle);
    }
    if (!duration) duration = opserv_conf.block_shun_duration;
    return shun_add(src_handle, mask, duration, reason, now, 1);
}

static MODCMD_FUNC(cmd_sblock)
{
    struct userNode *target;
    struct shun *shun;
    char *reason;

    target = GetUserH(argv[1]);
    if (!target) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    if (IsService(target)) {
        reply("MSG_SERVICE_IMMUNE", target->nick);
        return 0;
    }
    reason = (argc > 2) ? unsplit_string(argv+2, argc-2, NULL) : NULL;
    shun = opserv_shun(target, user->handle_info->handle, reason, 0);
    reply("OSMSG_SHUN_ISSUED", shun->target);
    return 1;
}

static MODCMD_FUNC(cmd_shun)
{
    unsigned long duration;
    char *reason;
    struct shun *shun;

    reason = unsplit_string(argv+3, argc-3, NULL);
    if (!is_shun(argv[1]) && !IsChannelName(argv[1]) && (argv[1][0] != '&')) {
        reply("MSG_INVALID_SHUN", argv[1]);
        return 0;
    }
    if (!argv[1][strspn(argv[1], "#&*?@.")] && (strlen(argv[1]) < 10)) {
        reply("OSMSG_STUPID_SHUN", argv[1]);
        return 0;
    }
    duration = ParseInterval(argv[2]);
    if (!duration) {
        reply("MSG_INVALID_DURATION", argv[2]);
        return 0;
    }
    shun = shun_add(user->handle_info->handle, argv[1], duration, reason, now, 1);
    reply("OSMSG_SHUN_ISSUED", shun->target);
    return 1;
}

static MODCMD_FUNC(cmd_unshun)
{
    if (shun_remove(argv[1], 1))
        reply("OSMSG_SHUN_REMOVED", argv[1]);
    else
        reply("OSMSG_SHUN_FORCE_REMOVED", argv[1]);
    return 1;
}

static MODCMD_FUNC(cmd_refreshs)
{
    if (argc > 1) {
        unsigned int count;
        dict_iterator_t it;
        struct server *srv;

        for (it=dict_first(servers), count=0; it; it=iter_next(it)) {
            srv = iter_data(it);
            if ((srv == self) || !match_ircglob(srv->name, argv[1]))
                continue;
            shun_refresh_server(srv);
            reply("OSMSG_SHUNS_ONE_REFRESHED", srv->name);
            count++;
        }
        if (!count) {
            reply("MSG_SERVER_UNKNOWN", argv[1]);
            return 0;
        }
    } else {
        shun_refresh_all();
        reply("OSMSG_SHUNS_REFRESHED");
    }
    return 1;
}

static void
opserv_ison(struct userNode *bot, struct userNode *tell, struct userNode *target, const char *message)
{
    struct modeNode *mn;
    unsigned int count, here_len, n, maxlen;
    char buff[MAXLEN];

    maxlen = tell->handle_info ? tell->handle_info->screen_width : 0;
    if (!maxlen)
        maxlen = MAX_LINE_SIZE;
    for (n=count=0; n<target->channels.used; n++) {
        mn = target->channels.list[n];
        here_len = strlen(mn->channel->name);
        if ((count + here_len + 4) > maxlen) {
            buff[count] = 0;
            send_message(tell, bot, message, buff);
            count = 0;
        }
        if (mn->modes & MODE_CHANOP)
            buff[count++] = '@';
        if (mn->modes & MODE_HALFOP)
            buff[count++] = '%';
        if (mn->modes & MODE_VOICE)
            buff[count++] = '+';
        memcpy(buff+count, mn->channel->name, here_len);
        count += here_len;
        buff[count++] = ' ';
    }
    if (count) {
        buff[count] = 0;
        send_message(tell, bot, message, buff);
    }
}

static MODCMD_FUNC(cmd_inviteme)
{
    struct userNode *target;

    if (argc < 2) {
        target = user;
    } else {
        target = GetUserH(argv[1]);
        if (!target) {
            reply("MSG_NICK_UNKNOWN", argv[1]);
            return 0;
        }
    }
    if (opserv_conf.debug_channel == NULL) {
        reply("OSMSG_NO_DEBUG_CHANNEL");
        return 0;
    }
    if (GetUserMode(opserv_conf.debug_channel, user)) {
        reply("OSMSG_ALREADY_THERE", opserv_conf.debug_channel->name);
        return 0;
    }
    irc_invite(cmd->parent->bot, target, opserv_conf.debug_channel);
    if (target != user)
        reply("OSMSG_INVITE_DONE", target->nick, opserv_conf.debug_channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_invite)
{
    if (GetUserMode(channel, user)) {
        reply("OSMSG_ALREADY_THERE", channel->name);
        return 0;
    }
    irc_invite(cmd->parent->bot, user, channel);
    return 1;
}

static MODCMD_FUNC(cmd_svsjoin)
{
    struct userNode *target;


    if(!IsChannelName(argv[2])) {
        reply("MSG_NOT_CHANNEL_NAME");
        return 0;
    }
    target = GetUserH(argv[1]);
    if (!target) {
       reply("MSG_NICK_UNKNOWN", argv[1]);
       return 0;
    }

    if (!(channel = GetChannel(argv[2]))) {
       channel = AddChannel(argv[2], now, NULL, NULL, NULL);
    }
    if (GetUserMode(channel, target)) {
        reply("OSMSG_USER_ALREADY_THERE", target->nick, channel->name);
        return 0;
    }
    irc_svsjoin(opserv, target, channel);
    reply("OSMSG_SVSJOIN_SENT");
    return 1;
}

static MODCMD_FUNC(cmd_svsnick)
{
    struct userNode *target;
    
    target = GetUserH(argv[1]);
    if (!target) {
       reply("MSG_NICK_UNKNOWN", argv[1]);
       return 0;
    }
    if(!is_valid_nick(argv[2])) {
       reply("OMSG_BAD_SVSNICK", argv[2]);
       return 0;
    }
    irc_svsnick(opserv, target, argv[2]);
    return 1;
}

static MODCMD_FUNC(cmd_join)
{
    struct userNode *bot = cmd->parent->bot;

    if (!IsChannelName(argv[1])) {
        reply("MSG_NOT_CHANNEL_NAME");
        return 0;
    } else if (!(channel = GetChannel(argv[1]))) {
        channel = AddChannel(argv[1], now, NULL, NULL, NULL);
        AddChannelUser(bot, channel)->modes |= MODE_CHANOP;
    } else if (GetUserMode(channel, bot)) {
        reply("OSMSG_ALREADY_JOINED", channel->name);
        return 0;
    } else {
        struct mod_chanmode change;
        mod_chanmode_init(&change);
        change.argc = 1;
        change.args[0].mode = MODE_CHANOP;
        change.args[0].u.member = AddChannelUser(bot, channel);
        modcmd_chanmode_announce(&change);
    }
    irc_fetchtopic(bot, channel->name);
    reply("OSMSG_JOIN_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_kick)
{
    struct userNode *target;
    char *reason;

    if (argc < 3) {
        reason = alloca(strlen(OSMSG_KICK_REQUESTED)+strlen(user->nick)+1);
        sprintf(reason, OSMSG_KICK_REQUESTED, user->nick);
    } else {
        reason = unsplit_string(argv+2, argc-2, NULL);
    }
    target = GetUserH(argv[1]);
    if (!target) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    if (!GetUserMode(channel, target)) {
        reply("OSMSG_NOT_ON_CHANNEL", target->nick, channel->name);
        return 0;
    }
    KickChannelUser(target, channel, cmd->parent->bot, reason);
    return 1;
}

static MODCMD_FUNC(cmd_kickall)
{
    unsigned int limit, n, inchan;
    struct modeNode *mn;
    char *reason;
    struct userNode *bot = cmd->parent->bot;

    /* ircu doesn't let servers KICK users, so if OpServ's not in the
     * channel, we have to join it in temporarily. */
    if (!(inchan = GetUserMode(channel, bot) ? 1 : 0)) {
        struct mod_chanmode change;
        mod_chanmode_init(&change);
        change.args[0].mode = MODE_CHANOP;
        change.args[0].u.member = AddChannelUser(bot, channel);
        modcmd_chanmode_announce(&change);
    }
    if (argc < 2) {
        reason = alloca(strlen(OSMSG_KICK_REQUESTED)+strlen(user->nick)+1);
        sprintf(reason, OSMSG_KICK_REQUESTED, user->nick);
    } else {
        reason = unsplit_string(argv+1, argc-1, NULL);
    }
    limit = user->handle_info->opserv_level;
    for (n=channel->members.used; n>0;) {
        mn = channel->members.list[--n];
        if (IsService(mn->user)
            || (mn->user->handle_info
                && (mn->user->handle_info->opserv_level >= limit))) {
            continue;
        }
        KickChannelUser(mn->user, channel, bot, reason);
    }
    if (!inchan)
        DelChannelUser(bot, channel, "My work here is done", 0);
    reply("OSMSG_KICKALL_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_kickban)
{
    struct mod_chanmode change;
    struct userNode *target;
    char *reason;
    char *mask;

    if (argc == 2) {
        reason = alloca(strlen(OSMSG_KICK_REQUESTED)+strlen(user->nick)+1);
        sprintf(reason, OSMSG_KICK_REQUESTED, user->nick);
    } else {
        reason = unsplit_string(argv+2, argc-2, NULL);
    }
    target = GetUserH(argv[1]);
    if (!target) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    if (!GetUserMode(channel, target)) {
        reply("OSMSG_NOT_ON_CHANNEL", target->nick, channel->name);
        return 0;
    }
    mod_chanmode_init(&change);
    change.argc = 1;
    change.args[0].mode = MODE_BAN;
    change.args[0].u.hostmask = mask = generate_hostmask(target, 0);
    modcmd_chanmode_announce(&change);
    KickChannelUser(target, channel, cmd->parent->bot, reason);
    free(mask);
    return 1;
}

static MODCMD_FUNC(cmd_kickbanall)
{
    struct modeNode *mn;
    struct userNode *bot = cmd->parent->bot;
    struct mod_chanmode *change;
    char *reason;
    unsigned int limit, n, inchan;

    /* ircu doesn't let servers KICK users, so if OpServ's not in the
     * channel, we have to join it in temporarily. */
    if (!(inchan = GetUserMode(channel, bot) ? 1 : 0)) {
        change = mod_chanmode_alloc(2);
        change->args[0].mode = MODE_CHANOP;
        change->args[0].u.member = AddChannelUser(bot, channel);
        change->args[1].mode = MODE_BAN;
        change->args[1].u.hostmask = "*!*@*";
    } else {
        change = mod_chanmode_alloc(1);
        change->args[0].mode = MODE_BAN;
        change->args[0].u.hostmask = "*!*@*";
    }
    modcmd_chanmode_announce(change);
    mod_chanmode_free(change);
    if (argc < 2) {
        reason = alloca(strlen(OSMSG_KICK_REQUESTED)+strlen(user->nick)+1);
        sprintf(reason, OSMSG_KICK_REQUESTED, user->nick);
    } else {
        reason = unsplit_string(argv+1, argc-1, NULL);
    }
    /* now kick them */
    limit = user->handle_info->opserv_level;
    for (n=channel->members.used; n>0; ) {
        mn = channel->members.list[--n];
        if (IsService(mn->user)
            || (mn->user->handle_info
                && (mn->user->handle_info->opserv_level >= limit))) {
            continue;
        }
        KickChannelUser(mn->user, channel, bot, reason);
    }
    if (!inchan)
        DelChannelUser(bot, channel, "My work here is done", 0);
    reply("OSMSG_KICKALL_DONE", channel->name);
    return 1;    
}

static MODCMD_FUNC(cmd_svspart)
{
    struct userNode *target;
    struct chanNode *target_channel;

    if(!IsChannelName(argv[2])) {
        reply("MSG_NOT_CHANNEL_NAME");
        return 0;
    }
    if(!(target_channel = GetChannel(argv[2])))
    {
        reply("MSG_INVALID_CHANNEL");
        return 0;
    }
    target = GetUserH(argv[1]);
    if (!target) {
       reply("MSG_NICK_UNKNOWN", argv[1]);
       return 0;
    }

    if (!GetUserMode(target_channel, target)) {
        reply("OSMSG_NOT_ON_CHANNEL", cmd->parent->bot->nick, target_channel->name);
        return 0;
    }

    irc_svspart(opserv, target, target_channel);
    reply("OSMSG_SVSPART_SENT");
    return 1;
}

static MODCMD_FUNC(cmd_part)
{
    char *reason;

    if (!IsChannelName(argv[1])) {
        reply("MSG_NOT_CHANNEL_NAME");
        return 0;
    }
    if ((channel = GetChannel(argv[1]))) {
        if (!GetUserMode(channel, cmd->parent->bot)) {
            reply("OSMSG_NOT_ON_CHANNEL", cmd->parent->bot->nick, channel->name);
            return 0;
        }
        reason = (argc < 3) ? "Leaving." : unsplit_string(argv+2, argc-2, NULL);
        reply("OSMSG_LEAVING", channel->name);
        DelChannelUser(cmd->parent->bot, channel, reason, 0);
    }
    return 1;
}

static MODCMD_FUNC(cmd_mode)
{
    if (!modcmd_chanmode(argv+1, argc-1, MCP_ALLOW_OVB|MCP_KEY_FREE|MC_ANNOUNCE)) {
        reply("MSG_INVALID_MODES", unsplit_string(argv+1, argc-1, NULL));
        return 0;
    }
    reply("OSMSG_MODE_SET", channel->name);
    return 1;
}

int is_valid_mark(char *mark)
{
    char *ptr; 

    if(!mark || !*mark)
        return 0;
    if(strlen(mark) > MARKLEN)
        return 0;

    for(ptr = mark; *ptr; ptr++) {
        if(! (isalnum(*ptr) || *ptr == '-'))
            return 0;
    }

    return 1;
}

static MODCMD_FUNC(cmd_mark) 
{
    char *mark = argv[2];
    struct userNode *victim = GetUserH(argv[1]);
    
    if(!victim)
        reply("MSG_NICK_UNKNOWN", argv[1]);
    else if(!is_valid_mark(mark))
        reply("OSMSG_MARK_INVALID");
    else {
        irc_mark(victim, mark);
        reply("OSMSG_MARK_SET");
        return 1;
    }
    return 0;
}

static MODCMD_FUNC(cmd_op)
{
    struct mod_chanmode *change;
    unsigned int arg, count;

    change = mod_chanmode_alloc(argc-1);
    for (arg = 1, count = 0; arg < argc; ++arg) {
        struct userNode *victim;
        struct modeNode *mn;
        if (!(victim = GetUserH(argv[arg])))
            continue;
        if (!(mn =  GetUserMode(channel, victim)))
            continue;
        if (mn->modes & MODE_CHANOP)
            continue;
        change->args[count].mode = MODE_CHANOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_OP_DONE");
    return 1;
}

static MODCMD_FUNC(cmd_hop)
{
    struct mod_chanmode *change;
    unsigned int arg, count;

    change = mod_chanmode_alloc(argc-1);
    for (arg = 1, count = 0; arg < argc; ++arg) {
        struct userNode *victim;
        struct modeNode *mn;
        if (!(victim = GetUserH(argv[arg])))
            continue;
        if (!(mn =  GetUserMode(channel, victim)))
            continue;
        if (mn->modes & MODE_HALFOP)
            continue;
        change->args[count].mode = MODE_HALFOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_HOP_DONE");
    return 1;
}

static MODCMD_FUNC(cmd_opall)
{
    struct mod_chanmode *change;
    unsigned int ii, count;

    change = mod_chanmode_alloc(channel->members.used);
    for (ii = count = 0; ii < channel->members.used; ++ii) {
        struct modeNode *mn = channel->members.list[ii];
        if (mn->modes & MODE_CHANOP)
            continue;
        change->args[count].mode = MODE_CHANOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_OPALL_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_hopall)
{
    struct mod_chanmode *change;
    unsigned int ii, count;

    change = mod_chanmode_alloc(channel->members.used);
    for (ii = count = 0; ii < channel->members.used; ++ii) {
        struct modeNode *mn = channel->members.list[ii];
        if (mn->modes & MODE_HALFOP)
            continue;
        change->args[count].mode = MODE_HALFOP;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_HOPALL_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_whois)
{
    struct userNode *target;
    char buffer[128];
    int bpos, herelen;

#ifdef WITH_PROTOCOL_P10
    if (argv[1][0] == '*')
        target = GetUserN(argv[1]+1);
    else
#endif
    target = GetUserH(argv[1]);
    if (!target) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    reply("OSMSG_WHOIS_NICK", target->nick);
    reply("OSMSG_WHOIS_HOST", target->ident, target->hostname);
    if (IsFakeHost(target))
        reply("OSMSG_WHOIS_FAKEHOST", target->fakehost);
    reply("OSMSG_WHOIS_CRYPT_HOST", target->crypthost);
    reply("OSMSG_WHOIS_CRYPT_IP", target->cryptip);
    reply("OSMSG_WHOIS_IP", irc_ntoa(&target->ip));

    if (target->city) {
        reply("OSMSG_WHOIS_COUNTRY", target->country_name);
        reply("OSMSG_WHOIS_COUNTRY_CODE", target->country_code);
        reply("OSMSG_WHOIS_CITY", target->city);
        reply("OSMSG_WHOIS_REGION", target->region);

        reply("OSMSG_WHOIS_POSTAL_CODE", target->postal_code);
        reply("OSMSG_WHOIS_LATITUDE", target->latitude);
        reply("OSMSG_WHOIS_LONGITUDE", target->longitude);
        /* Only show a map url if we have a city, latitude and longitude.
         * Theres not much point of latitude and longitude coordinates are
         * returned but no city, the coordinates are useless.
         */
        if (target->latitude && target->longitude && target->city) {
            char map_url[MAXLEN];
            snprintf(map_url, sizeof(map_url), "http://www.mapquest.com/maps/map.adp?searchtype=address&formtype=address&latlongtype=decimal&latitude=%f&longitude=%f",
                     target->latitude, target->longitude);
            reply("OSMSG_WHOIS_MAP", map_url);
        }
        reply("OSMSG_WHOIS_DMA_CODE", target->dma_code);
        reply("OSMSG_WHOIS_AREA_CODE", target->area_code);
    } else if (target->country_name) {
        reply("OSMSG_WHOIS_COUNTRY", target->country_name);
    }
    if(target->version_reply) {
        reply("OSMSG_WHOIS_VERSION", target->version_reply);
    }
    if(target->mark) {
        reply("OSMSG_WHOIS_MARK", target->mark);
    }
    reply("OSMSG_WHOIS_NO_NOTICE", target->no_notice ? "YES":"NO");
  
    if (target->modes) {
        bpos = 0;
#define buffer_cat(str) (herelen = strlen(str), memcpy(buffer+bpos, str, herelen), bpos += herelen)
        if (IsInvisible(target)) buffer[bpos++] = 'i';
        if (IsWallOp(target)) buffer[bpos++] = 'w';
        if (IsOper(target)) buffer[bpos++] = 'o';
        if (IsGlobal(target)) buffer[bpos++] = 'g';
        if (IsServNotice(target)) buffer[bpos++] = 's';

        // sethost - reed/apples
        // if (IsHelperIrcu(target)) buffer[bpos++] = 'h';
        if (IsSetHost(target)) buffer[bpos++] = 'h';

        if (IsService(target)) buffer[bpos++] = 'k';
        if (IsDeaf(target)) buffer[bpos++] = 'd';
        if (target->handle_info) buffer[bpos++] = 'r';
        if (IsHiddenHost(target)) buffer[bpos++] = 'x';
	if (IsBotM(target)) buffer[bpos++] = 'B';
	if (IsHideChans(target)) buffer[bpos++] = 'n';
	if (IsHideIdle(target)) buffer[bpos++] = 'I';
	if (IsXtraOp(target)) buffer[bpos++] = 'X';
        if (IsGagged(target)) buffer_cat(" (gagged)");
        if (IsRegistering(target)) buffer_cat(" (registered account)");
        buffer[bpos] = 0;
        if (bpos > 0)
            reply("OSMSG_WHOIS_MODES", buffer);
    }
    reply("OSMSG_WHOIS_INFO", target->info);
#ifdef WITH_PROTOCOL_P10
    reply("OSMSG_WHOIS_NUMERIC", target->numeric);
#endif
    reply("OSMSG_WHOIS_SERVER", target->uplink->name);
    reply("OSMSG_WHOIS_ACCOUNT", (target->handle_info ? target->handle_info->handle : "Not authenticated"));

    reply("OSMSG_WHOIS_PRIVS", client_report_privs(target));

    intervalString(buffer, now - target->timestamp, user->handle_info);
    reply("OSMSG_WHOIS_NICK_AGE", buffer);
    if (target->channels.used <= MAX_CHANNELS_WHOIS)
        opserv_ison(cmd->parent->bot, user, target, "OSMSG_WHOIS_CHANNELS");
    else
        reply("OSMSG_WHOIS_HIDECHANS");
    return 1;
}

static MODCMD_FUNC(cmd_unban)
{
    struct mod_chanmode change;
    mod_chanmode_init(&change);
    change.argc = 1;
    change.args[0].mode = MODE_REMOVE | MODE_BAN;
    change.args[0].u.hostmask = argv[1];
    modcmd_chanmode_announce(&change);
    reply("OSMSG_UNBAN_DONE", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_voiceall)
{
    struct mod_chanmode *change;
    unsigned int ii, count;

    change = mod_chanmode_alloc(channel->members.used);
    for (ii = count = 0; ii < channel->members.used; ++ii) {
        struct modeNode *mn = channel->members.list[ii];
        if (mn->modes & (MODE_CHANOP|MODE_HALFOP|MODE_VOICE))
            continue;
        change->args[count].mode = MODE_VOICE;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_CHANNEL_VOICED", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_devoiceall)
{
    struct mod_chanmode *change;
    unsigned int ii, count;

    change = mod_chanmode_alloc(channel->members.used);
    for (ii = count = 0; ii < channel->members.used; ++ii) {
        struct modeNode *mn = channel->members.list[ii];
        if (!(mn->modes & MODE_VOICE))
            continue;
        change->args[count].mode = MODE_REMOVE | MODE_VOICE;
        change->args[count++].u.member = mn;
    }
    if (count) {
        change->argc = count;
        modcmd_chanmode_announce(change);
    }
    mod_chanmode_free(change);
    reply("OSMSG_CHANNEL_DEVOICED", channel->name);
    return 1;
}

static MODCMD_FUNC(cmd_stats_bad) {
    dict_iterator_t it;
    unsigned int ii, end, here_len;
    char buffer[400];

    /* Show the bad word list.. */
    /* TODO: convert nonprinting chars like bold to $b etc in a usable way */
    for (ii=end=0; ii<opserv_bad_words->used; ii++) {
        here_len = strlen(opserv_bad_words->list[ii]);
        /* If the line is full output it & start again */
        if ((end + here_len + 2) > sizeof(buffer)) {
            buffer[end] = 0;
            reply("OSMSG_BADWORD_LIST", buffer);
            end = 0;
        }
        memcpy(buffer+end, opserv_bad_words->list[ii], here_len);
        end += here_len;
        buffer[end++] = ' ';
    }
    buffer[end] = 0;
    reply("OSMSG_BADWORD_LIST", buffer);

    /* Show the exemption list.. */
    for (it=dict_first(opserv_exempt_channels), end=0; it; it=iter_next(it)) {
        here_len = strlen(iter_key(it));
        if ((end + here_len + 2) > sizeof(buffer)) {
            buffer[end] = 0;
            reply("OSMSG_EXEMPTED_LIST", buffer);
            end = 0;
        }
        memcpy(buffer+end, iter_key(it), here_len);
        end += here_len;
        buffer[end++] = ' ';
    }
    buffer[end] = 0;
    reply("OSMSG_EXEMPTED_LIST", buffer);
    return 1;
}

static MODCMD_FUNC(cmd_stats_glines) {
    reply("OSMSG_GLINE_COUNT", gline_count());
    return 1;
}

static MODCMD_FUNC(cmd_stats_shuns) {
    reply("OSMSG_SHUN_COUNT", shun_count());
    return 1;
}

static void
trace_links(struct userNode *bot, struct userNode *user, struct server *server, unsigned int depth) {
    unsigned int nn, pos;
    char buffer[400];

    for (nn=1; nn<=depth; nn<<=1) ;
    for (pos=0, nn>>=1; nn>1; ) {
        nn >>= 1;
        buffer[pos++] = (depth & nn) ? ((nn == 1) ? '`' : ' ') : '|';
        buffer[pos++] = (nn == 1) ? '-': ' ';
    }
    buffer[pos] = 0;
    send_message(user, bot, "OSMSG_LINKS_SERVER", buffer, server->name, server->clients, server->description);
    if (!server->children.used)
        return;
    for (nn=0; nn<server->children.used-1; nn++) {
        trace_links(bot, user, server->children.list[nn], depth<<1);
    }
    trace_links(bot, user, server->children.list[nn], (depth<<1)|1);
}

static MODCMD_FUNC(cmd_stats_links) {
    trace_links(cmd->parent->bot, user, self, 1);
    return 1;
}


static MODCMD_FUNC(cmd_stats_max) {
    reply("OSMSG_MAX_CLIENTS", max_clients, asctime(localtime(&max_clients_time)));
    return 1;
}

static MODCMD_FUNC(cmd_stats_network) {
    struct helpfile_table tbl;
    unsigned int nn, tot_clients;
    dict_iterator_t it;

    tot_clients = dict_size(clients);
    reply("OSMSG_NETWORK_INFO", tot_clients, invis_clients, curr_opers.used);
    tbl.length = dict_size(servers)+1;
    tbl.width = 3;
    tbl.flags = TABLE_NO_FREE;
    tbl.contents = calloc(tbl.length, sizeof(*tbl.contents));
    tbl.contents[0] = calloc(tbl.width, sizeof(**tbl.contents));
    tbl.contents[0][0] = "Server Name";
    tbl.contents[0][1] = "Clients";
    tbl.contents[0][2] = "Load";
    for (it=dict_first(servers), nn=1; it; it=iter_next(it)) {
        struct server *server = iter_data(it);
        char *buffer = malloc(32);
        tbl.contents[nn] = calloc(tbl.width, sizeof(**tbl.contents));
        tbl.contents[nn][0] = server->name;
        tbl.contents[nn][1] = buffer;
        sprintf(buffer, "%u", server->clients);
        tbl.contents[nn][2] = buffer + 16;
        sprintf(buffer+16, "%3.3g%%", ((double)server->clients/tot_clients)*100);
        nn++;
    }
    table_send(cmd->parent->bot, user->nick, 0, 0, tbl);
    for (nn=1; nn<tbl.length; nn++) {
        free((char*)tbl.contents[nn][1]);
        free(tbl.contents[nn]);
    }
    free(tbl.contents[0]);
    free(tbl.contents);
    return 1;
}

static MODCMD_FUNC(cmd_stats_network2) {
    struct helpfile_table tbl;
    unsigned int nn;
    dict_iterator_t it;

    tbl.length = dict_size(servers)+1;
    tbl.width = 3;
    tbl.flags = TABLE_NO_FREE;
    tbl.contents = calloc(tbl.length, sizeof(*tbl.contents));
    tbl.contents[0] = calloc(tbl.width, sizeof(**tbl.contents));
    tbl.contents[0][0] = "Server Name";
    tbl.contents[0][1] = "Numeric";
    tbl.contents[0][2] = "Link Time";
    for (it=dict_first(servers), nn=1; it; it=iter_next(it)) {
        struct server *server = iter_data(it);
        char *buffer = malloc(64);
        int ofs;

        tbl.contents[nn] = calloc(tbl.width, sizeof(**tbl.contents));
        tbl.contents[nn][0] = server->name;
#ifdef WITH_PROTOCOL_P10
        sprintf(buffer, "%s (%ld)", server->numeric, base64toint(server->numeric, strlen(server->numeric)));
#else
        buffer[0] = 0;
#endif
        tbl.contents[nn][1] = buffer;
        ofs = strlen(buffer) + 1;
        intervalString(buffer + ofs, now - server->link, user->handle_info);
        if (server->self_burst)
            strcat(buffer + ofs, " Bursting");
        tbl.contents[nn][2] = buffer + ofs;
        nn++;
    }
    table_send(cmd->parent->bot, user->nick, 0, 0, tbl);
    for (nn=1; nn<tbl.length; nn++) {
        free((char*)tbl.contents[nn][1]);
        free(tbl.contents[nn]);
    }
    free(tbl.contents[0]);
    free(tbl.contents);
    return 1;
}

static MODCMD_FUNC(cmd_stats_reserved) {
    dict_iterator_t it;

    reply("OSMSG_RESERVED_LIST");
    for (it = dict_first(opserv_reserved_nick_dict); it; it = iter_next(it))
        send_message_type(4, user, cmd->parent->bot, "%s", iter_key(it));
    return 1;
}

static MODCMD_FUNC(cmd_stats_trusted) {
    dict_iterator_t it;
    struct trusted_host *th;
    char length[INTERVALLEN], issued[INTERVALLEN], limit[32];

    reply("OSMSG_TRUSTED_LIST");
    reply("OSMSG_TRUSTED_LIST_BAR");
    reply("OSMSG_TRUSTED_LIST_HEADER");
    reply("OSMSG_TRUSTED_LIST_BAR");
    if (argc > 1) {
        th = dict_find(opserv_trusted_hosts, argv[1], NULL);
        if (th) {
            if (th->issued)
                intervalString(issued, now - th->issued, user->handle_info);
            if (th->expires)
                intervalString(length, th->expires - now, user->handle_info);
            if (th->limit)
                sprintf(limit, "%lu", th->limit);
            reply("OSMSG_HOST_IS_TRUSTED",
                  th->ipaddr,
                  (th->limit ? limit : "none"),
                  (th->issuer ? th->issuer : "<unknown>"),
                  (th->issued ? issued : "some time"),
                  (th->expires ? length : "never"));
            reply("OSMSG_HOST_IS_TRUSTED_DESC", (th->reason ? th->reason : "<unknown>"));
        } else {
            reply("OSMSG_HOST_NOT_TRUSTED", argv[1]);
        }
    } else {
        for (it = dict_first(opserv_trusted_hosts); it; it = iter_next(it)) {
            th = iter_data(it);
            if (th->issued)
                intervalString(issued, now - th->issued, user->handle_info);
            if (th->expires)
                intervalString(length, th->expires - now, user->handle_info);
            if (th->limit)
                sprintf(limit, "%lu", th->limit);
            reply("OSMSG_HOST_IS_TRUSTED", iter_key(it),
                  (th->limit ? limit : "none"),
                  (th->issuer ? th->issuer : "<unknown>"),
                  (th->issued ? issued : "some time"),
                  (th->expires ? length : "never"));
            reply("OSMSG_HOST_IS_TRUSTED_DESC", (th->reason ? th->reason : "<unknown>"));
        }
    }
    reply("OSMSG_TRUSTED_LIST_END");
    return 1;
}

static MODCMD_FUNC(cmd_stats_uplink) {
    extern struct cManagerNode cManager;
    struct uplinkNode *uplink;

    uplink = cManager.uplink;
    reply("OSMSG_UPLINK_START", uplink->name);
    reply("OSMSG_UPLINK_ADDRESS", uplink->host, uplink->port);
    return 1;
}

static MODCMD_FUNC(cmd_stats_uptime) {
    char uptime[INTERVALLEN];
    struct tms buf;
    extern time_t boot_time;
    extern int lines_processed;
    static long clocks_per_sec;

    if (!clocks_per_sec) {
#if defined(HAVE_SYSCONF) && defined(_SC_CLK_TCK)
        clocks_per_sec = sysconf(_SC_CLK_TCK);
        if (clocks_per_sec <= 0)
#endif
        {
            log_module(OS_LOG, LOG_ERROR, "Unable to query sysconf(_SC_CLK_TCK), output of 'stats uptime' will be wrong");
            clocks_per_sec = CLOCKS_PER_SEC;
        }
    }
    intervalString(uptime, time(NULL)-boot_time, user->handle_info);
    times(&buf);
    reply("OSMSG_UPTIME_STATS",
          uptime, lines_processed,
          buf.tms_utime/(double)clocks_per_sec,
          buf.tms_stime/(double)clocks_per_sec);
    return 1;
}

static MODCMD_FUNC(cmd_stats_alerts) {
    dict_iterator_t it;
    struct opserv_user_alert *alert;
    const char *reaction;
    char t_buffer[INTERVALLEN];
    char *m = NULL;

    if(argc > 1) 
        m = unsplit_string(argv + 1, argc - 1, NULL);
    reply("OSMSG_ALERTS_LIST", m ? m : "*");
    reply("OSMSG_ALERTS_BAR");
    reply("OSMSG_ALERTS_HEADER");
    reply("OSMSG_ALERTS_BAR");
    for (it = dict_first(opserv_user_alerts); it; it = iter_next(it)) {
        alert = iter_data(it);
        if(m && (!match_ircglob(alert->text_discrim, m) && strcasecmp(alert->owner, m) && strcasecmp(iter_key(it), m)))
             continue; /* not a match to requested filter */
        switch (alert->reaction) {
        case REACT_NOTICE: reaction = "notice"; break;
        case REACT_KILL: reaction = "kill"; break;
//        case REACT_SILENT: reaction = "silent"; break;
        case REACT_GLINE: reaction = "gline"; break;
        case REACT_TRACK: reaction = "track"; break;
        case REACT_SHUN: reaction = "shun"; break;
        case REACT_SVSJOIN: reaction = "svsjoin"; break;
        case REACT_SVSPART: reaction = "svspart"; break;
        case REACT_VERSION: reaction = "version"; break;
        case REACT_MARK: reaction = "mark"; break;
        default: reaction = "<unknown>"; break;
        }
        reply("OSMSG_ALERT_IS", iter_key(it), reaction, alert->owner);
        reply("OSMSG_ALERTS_DESC", alert->text_discrim);
        if (alert->last > 0)
          reply("OSMSG_ALERTS_LAST", intervalString(t_buffer, now - alert->last, user->handle_info));
        else
          reply("OSMSG_ALERTS_LAST", "Never");
    }
    reply("OSMSG_ALERT_END");
    return 1;
}

static MODCMD_FUNC(cmd_stats_gags) {
    struct gag_entry *gag;
    struct helpfile_table table;
    unsigned int nn;

    if (!gagList) {
        reply("OSMSG_NO_GAGS");
        return 1;
    }
    for (nn=0, gag=gagList; gag; nn++, gag=gag->next) ;
    table.length = nn+1;
    table.width = 4;
    table.flags = TABLE_NO_FREE;
    table.contents = calloc(table.length, sizeof(char**));
    table.contents[0] = calloc(table.width, sizeof(char*));
    table.contents[0][0] = "Mask";
    table.contents[0][1] = "Owner";
    table.contents[0][2] = "Expires";
    table.contents[0][3] = "Reason";
    for (nn=1, gag=gagList; gag; nn++, gag=gag->next) {
        char expstr[INTERVALLEN];
        if (gag->expires)
            intervalString(expstr, gag->expires - now, user->handle_info);
        else
            strcpy(expstr, "Never");
        table.contents[nn] = calloc(table.width, sizeof(char*));
        table.contents[nn][0] = gag->mask;
        table.contents[nn][1] = gag->owner;
        table.contents[nn][2] = strdup(expstr);
        table.contents[nn][3] = gag->reason;
    }
    table_send(cmd->parent->bot, user->nick, 0, NULL, table);
    for (nn=1; nn<table.length; nn++) {
        free((char*)table.contents[nn][2]);
        free(table.contents[nn]);
    }
    free(table.contents[0]);
    free(table.contents);
    return 1;
}

static MODCMD_FUNC(cmd_stats_timeq) {
    reply("OSMSG_TIMEQ_INFO", timeq_size(), timeq_next()-now);
    return 1;
}

/*
static MODCMD_FUNC(cmd_stats_warn) {
    dict_iterator_t it;

    reply("OSMSG_WARN_LISTSTART");
    for (it=dict_first(opserv_chan_warn); it; it=iter_next(it))
        reply("OSMSG_WARN_LISTENTRY", iter_key(it), (char*)iter_data(it));
    reply("OSMSG_WARN_LISTEND");
    return 1;
}
*/

#if defined(WITH_MALLOC_X3)
static MODCMD_FUNC(cmd_stats_memory) {
    extern unsigned long alloc_count, alloc_size;
    send_message_type(MSG_TYPE_NOXLATE, user, cmd->parent->bot,
                      "%u allocations totalling %u bytes.",
                      alloc_count, alloc_size);
    return 1;
}
#elif defined(WITH_MALLOC_SLAB)
static MODCMD_FUNC(cmd_stats_memory) {
    extern unsigned long slab_alloc_count, slab_count, slab_alloc_size;
    extern unsigned long big_alloc_count, big_alloc_size;
    send_message_type(MSG_TYPE_NOXLATE, user, cmd->parent->bot,
                      "%u allocations in %u slabs totalling %u bytes.",
                      slab_alloc_count, slab_count, slab_alloc_size);
    send_message_type(MSG_TYPE_NOXLATE, user, cmd->parent->bot,
                      "%u big allocations totalling %u bytes.",
                      big_alloc_count, big_alloc_size);
    return 1;
}
#endif

static MODCMD_FUNC(cmd_dump)
{
    char linedup[MAXLEN], original[MAXLEN];

    unsplit_string(argv+1, argc-1, original);
    safestrncpy(linedup, original, sizeof(linedup));
    /* assume it's only valid IRC if we can parse it */
    if (parse_line(linedup, 1)) {
        irc_raw(original);
        reply("OSMSG_LINE_DUMPED");
    } else
        reply("OSMSG_RAW_PARSE_ERROR");
    return 1;
}

static MODCMD_FUNC(cmd_raw)
{
    char linedup[MAXLEN], original[MAXLEN];

    unsplit_string(argv+1, argc-1, original);
    safestrncpy(linedup, original, sizeof(linedup));
    /* Try to parse the line before sending it; if it's too wrong,
     * maybe it will core us instead of our uplink. */
    parse_line(linedup, 1);
    irc_raw(original);
    reply("OSMSG_LINE_DUMPED");
    return 1;
}

static struct userNode *
opserv_add_reserve(struct svccmd *cmd, struct userNode *user, const char *nick, const char *ident, const char *host, const char *desc)
{
    struct userNode *resv = GetUserH(nick);
    if (resv) {
        if (IsService(resv)) {
            reply("MSG_SERVICE_IMMUNE", resv->nick);
            return NULL;
        }
        if (resv->handle_info
            && resv->handle_info->opserv_level > user->handle_info->opserv_level) {
            reply("OSMSG_LEVEL_TOO_LOW");
            return NULL;
        }
    }
    if ((resv = AddClone(nick, ident, host, desc))) {
        dict_insert(opserv_reserved_nick_dict, resv->nick, resv);
    }
    return resv;
}

static MODCMD_FUNC(cmd_collide)
{
    struct userNode *resv;

    resv = opserv_add_reserve(cmd, user, argv[1], argv[2], argv[3], unsplit_string(argv+4, argc-4, NULL));
    if (resv) {
        reply("OSMSG_COLLIDED_NICK", resv->nick);
        return 1;
    } else {
        reply("OSMSG_CLONE_FAILED", argv[1]);
        return 0;
    }
}

static MODCMD_FUNC(cmd_reserve)
{
    struct userNode *resv;

    resv = opserv_add_reserve(cmd, user, argv[1], argv[2], argv[3], unsplit_string(argv+4, argc-4, NULL));
    if (resv) {
        resv->modes |= FLAGS_PERSISTENT;
        reply("OSMSG_RESERVED_NICK", resv->nick);
        return 1;
    } else {
        reply("OSMSG_CLONE_FAILED", argv[1]);
        return 0;
    }
}

static int
free_reserve(char *nick)
{
    struct userNode *resv;
    unsigned int rlen;
    char *reason;

    resv = dict_find(opserv_reserved_nick_dict, nick, NULL);
    if (!resv)
        return 0;

    rlen = strlen(resv->nick)+strlen(OSMSG_PART_REASON);
    reason = alloca(rlen);
    snprintf(reason, rlen, OSMSG_PART_REASON, resv->nick);
    DelUser(resv, NULL, 1, reason);
    dict_remove(opserv_reserved_nick_dict, nick);
    return 1;
}

static MODCMD_FUNC(cmd_unreserve)
{
    if (free_reserve(argv[1]))
        reply("OSMSG_NICK_UNRESERVED", argv[1]);
    else
        reply("OSMSG_NOT_RESERVED", argv[1]);
    return 1;
}

static void
opserv_part_channel(void *data)
{
    DelChannelUser(opserv, data, "Leaving.", 0);
}

static int alert_check_user(const char *key, void *data, void *extra);

static int
opserv_new_user_check(struct userNode *user)
{
    struct opserv_hostinfo *ohi;
    struct gag_entry *gag;
    char addr[IRC_NTOP_MAX_SIZE];

    /* Check to see if we should ignore them entirely. */
    if (IsLocal(user) || IsService(user))
        return 0;

    /* Check for alerts, and stop if we find one that kills them. */
    if (dict_foreach(opserv_user_alerts, alert_check_user, user))
        return 1;

    /* Gag them if appropriate. */
    for (gag = gagList; gag; gag = gag->next) {
        if (user_matches_glob(user, gag->mask, MATCH_USENICK)) {
            gag_helper_func(user, NULL);
            break;
        }
    }

    /* Add to host info struct */
    irc_ntop(addr, sizeof(addr), &user->ip);
    if (!(ohi = dict_find(opserv_hostinfo_dict, addr, NULL))) {
        ohi = calloc(1, sizeof(*ohi));
        dict_insert(opserv_hostinfo_dict, strdup(addr), ohi);
        userList_init(&ohi->clients);
    }
    userList_append(&ohi->clients, user);

    /* Only warn of new user floods outside of bursts. */
    if (!user->uplink->burst) {
        if (!policer_conforms(&opserv_conf.new_user_policer, now, 10)) {
            if (!new_user_flood) {
                new_user_flood = 1;
                opserv_alert("Warning: Possible new-user flood.");
            }
        } else {
            new_user_flood = 0;
        }
    }

    if (checkDefCon(DEFCON_NO_NEW_CLIENTS)) {
        DelUser(user, opserv, 1, DefConGlineReason);
        return 0;
    }

    if ( (checkDefCon(DEFCON_GLINE_NEW_CLIENTS) || checkDefCon(DEFCON_SHUN_NEW_CLIENTS)) && !IsOper(user)) {
        char target[IRC_NTOP_MAX_SIZE + 3] = { '*', '@', '\0' };

        strcpy(target + 2, user->hostname);
        if (checkDefCon(DEFCON_GLINE_NEW_CLIENTS))
            gline_add(opserv->nick, target, DefConGlineExpire, DefConGlineReason, now, 1, 0);
        else if (checkDefCon(DEFCON_SHUN_NEW_CLIENTS))
            shun_add(opserv->nick, target, DefConGlineExpire, DefConGlineReason, now, 1);
          
        return 0;
    }

    /* Only warn or G-line if there's an untrusted max and their IP is sane. */
    if (opserv_conf.untrusted_max
        && irc_in_addr_is_valid(user->ip)
        && !irc_in_addr_is_loopback(user->ip)) {
        struct trusted_host *th = dict_find(opserv_trusted_hosts, addr, NULL);
        unsigned int limit = th ? th->limit : opserv_conf.untrusted_max;

        if (checkDefCon(DEFCON_REDUCE_SESSION) && !th)
            limit = DefConSessionLimit;

        if (!limit) {
            /* 0 means unlimited hosts */
        } else if (ohi->clients.used == limit) {
            unsigned int nn;
            for (nn=0; nn<ohi->clients.used; nn++)
                send_message(ohi->clients.list[nn], opserv, "OSMSG_CLONE_WARNING");
        } else if (ohi->clients.used > limit) {
            char target[IRC_NTOP_MAX_SIZE + 3] = { '*', '@', '\0' };
            strcpy(target + 2, addr);
            gline_add(opserv->nick, target, opserv_conf.clone_gline_duration, "Excessive connections from a single host.", now, 1, 1);
        }
    }

    return 0;
}

static void
opserv_user_cleanup(struct userNode *user, UNUSED_ARG(struct userNode *killer), UNUSED_ARG(const char *why))
{
    struct opserv_hostinfo *ohi;
    char addr[IRC_NTOP_MAX_SIZE];

    if (IsLocal(user)) {
        /* Try to remove it from the reserved nick dict without
         * calling free_reserve, because that would call DelUser(),
         * and we'd loop back to here. */
        dict_remove(opserv_reserved_nick_dict, user->nick);
        return;
    }
    irc_ntop(addr, sizeof(addr), &user->ip);
    if ((ohi = dict_find(opserv_hostinfo_dict, addr, NULL))) {
        userList_remove(&ohi->clients, user);
        if (ohi->clients.used == 0)
            dict_remove(opserv_hostinfo_dict, addr);
    }
}

int
opserv_bad_channel(const char *name)
{
    unsigned int found;
    int present;

    dict_find(opserv_exempt_channels, name, &present);
    if (present)
        return 0;

    if (gline_find(name))
        return 1;

    for (found=0; found<opserv_bad_words->used; ++found)
        if (irccasestr(name, opserv_bad_words->list[found]))
            return 1;

    return 0;
}

static void
opserv_shutdown_channel(struct chanNode *channel, const char *reason)
{
    struct mod_chanmode *change;
    unsigned int nn;

    change = mod_chanmode_alloc(2);
    change->modes_set = MODE_SECRET | MODE_INVITEONLY;
    change->args[0].mode = MODE_CHANOP;
    change->args[0].u.member = AddChannelUser(opserv, channel);
    change->args[1].mode = MODE_BAN;
    change->args[1].u.hostmask = "*!*@*";
    mod_chanmode_announce(opserv, channel, change);
    mod_chanmode_free(change);
    for (nn=channel->members.used; nn>0; ) {
        struct modeNode *mNode = channel->members.list[--nn];
        if (IsService(mNode->user))
            continue;
        KickChannelUser(mNode->user, channel, opserv, user_find_message(mNode->user, reason));
    }
    timeq_add(now + opserv_conf.purge_lock_delay, opserv_part_channel, channel);
}

static void
opserv_channel_check(struct chanNode *newchan)
{
    /*char *warning; */

    if (!newchan->join_policer.params) {
        newchan->join_policer.last_req = now;
        newchan->join_policer.params = opserv_conf.join_policer_params;
    }
    /*
    if ((warning = dict_find(opserv_chan_warn, newchan->name, NULL))) {
        global_message_args(MESSAGE_RECIPIENT_OPERS, "OSMSG_CHANNEL_ACTIVITY_WARN", newchan->name, warning);
    }
    */

    /* Wait until the join check to shut channels down. */
    newchan->bad_channel = opserv_bad_channel(newchan->name);
}

static void
opserv_channel_delete(struct chanNode *chan)
{
    timeq_del(0, opserv_part_channel, chan, TIMEQ_IGNORE_WHEN);
}

static void
opserv_notice_handler(struct userNode *user, struct userNode *bot, char *text, UNUSED_ARG(int server_qualified))
{
    char *cmd; 
    /* if its a version reply, do an alert check (only alerts with version=something) */
    if(bot == opserv) {
        if(text[0] == '\001') {
            text++;
            cmd = mysep(&text, " ");
            if(cmd && !irccasecmp(cmd, "VERSION")) {
                char *version = mysep(&text, "\n");
                if(!version)
                    version = "";
                /* opserv_debug("Opserv got CTCP VERSION Notice from %s: %s", user->nick, version); */
                /* user->version_reply = strdup(version); done in parse-p10.c now */
                dict_foreach(opserv_user_alerts, alert_check_user, user);
            }
        }
    }
}

static int
opserv_join_check(struct modeNode *mNode)
{
    struct userNode *user = mNode->user;
    struct chanNode *channel = mNode->channel;
    const char *msg;

    if (IsService(user))
        return 0;

    dict_foreach(opserv_channel_alerts, alert_check_user, user);

    if (channel->bad_channel) {
        opserv_debug("Found $b%s$b in bad-word channel $b%s$b; removing the user.", user->nick, channel->name);
        if (channel->name[0] != '#')
            DelUser(user, opserv, 1, "OSMSG_ILLEGAL_KILL_REASON");
        else if (!GetUserMode(channel, opserv))
            opserv_shutdown_channel(channel, "OSMSG_ILLEGAL_REASON");
        else {
            send_message(user, opserv, "OSMSG_ILLEGAL_CHANNEL", channel->name);
            msg = user_find_message(user, "OSMSG_ILLEGAL_REASON");
            KickChannelUser(user, channel, opserv, msg);
        }
        return 1;
    }

    if (user->uplink->burst)
        return 0;
    if (policer_conforms(&channel->join_policer, now, 1.0)) {
        channel->join_flooded = 0;
        return 0;
    }
    if (!channel->join_flooded) {
        /* Don't moderate the channel unless it is activated and
           the number of users in the channel is over the threshold. */
        struct mod_chanmode change;
        mod_chanmode_init(&change);
        channel->join_flooded = 1;
        if (opserv_conf.join_flood_moderate && (channel->members.used > opserv_conf.join_flood_moderate_threshold)) {
            if (!GetUserMode(channel, opserv)) {
                /* If we aren't in the channel, join it. */
                change.args[0].mode = MODE_CHANOP;
                change.args[0].u.member = AddChannelUser(opserv, channel);
                change.argc++;
            }
            if (!(channel->modes & MODE_MODERATED))
                change.modes_set |= MODE_MODERATED;
            if (change.modes_set || change.argc)
                mod_chanmode_announce(opserv, channel, &change);
            send_target_message(0, channel->name, opserv, "OSMSG_FLOOD_MODERATE");
            opserv_alert("Warning: Possible join flood in %s (currently %d users; channel moderated).", channel->name, channel->members.used);
        } else {
            opserv_alert("Warning: Possible join flood in %s (currently %d users).", channel->name, channel->members.used);
        }
    }
    log_module(OS_LOG, LOG_INFO, "Join to %s during flood: "IDENT_FORMAT, channel->name, IDENT_DATA(user));
    return 0;
}

static int
opserv_add_bad_word(struct svccmd *cmd, struct userNode *user, const char *new_bad) {
    unsigned int bad_idx;

    for (bad_idx = 0; bad_idx < opserv_bad_words->used; ++bad_idx) {
        char *orig_bad = opserv_bad_words->list[bad_idx];
        if (irccasestr(new_bad, orig_bad)) {
            if (user)
                reply("OSMSG_BAD_REDUNDANT", new_bad, orig_bad);
            return 0;
        } else if (irccasestr(orig_bad, new_bad)) {
            if (user)
                reply("OSMSG_BAD_GROWING", orig_bad, new_bad);
            free(orig_bad);
            opserv_bad_words->list[bad_idx] = strdup(new_bad);
            for (bad_idx++; bad_idx < opserv_bad_words->used; bad_idx++) {
                orig_bad = opserv_bad_words->list[bad_idx];
                if (!irccasestr(orig_bad, new_bad))
                    continue;
                if (user)
                    reply("OSMSG_BAD_NUKING", orig_bad);
                string_list_delete(opserv_bad_words, bad_idx);
                bad_idx--;
                free(orig_bad);
            }
            return 1;
        }
    }
    string_list_append(opserv_bad_words, strdup(new_bad));
    if (user)
        reply("OSMSG_ADDED_BAD", new_bad);
    return 1;
}

static int
opserv_routing_plan_add_server(struct routingPlan *rp, const char *name, const char *uplink, const unsigned int port, int karma, const char *second, const unsigned int offline)
{
    struct routingPlanServer *rps;
    rps = calloc(1, sizeof(*rps));
    if(!rps)
        return 0;
    /* duplicate servers replace */
    rps->uplink = strdup(uplink);
    if(second)
        rps->secondaryuplink = strdup(second);
    else
        rps->secondaryuplink = NULL;
    rps->port = port ? port : 4400; /* lame hardcodede default port. maybe get from config file somewhere? */
    rps->karma = karma;
    rps->offline = offline; /* 1 = yes, 0 = no */
    dict_insert(rp->servers, strdup(name), rps);
    log_module(OS_LOG, LOG_DEBUG, "Adding rp server %s with uplink %s", name, uplink);
    return 1;
}

static void
free_routing_plan_server(void *data)
{
    struct routingPlanServer *rps = data;
    free(rps->uplink);
    if(rps->secondaryuplink)
        free(rps->secondaryuplink);
    free(rps);
}
 
struct routingPlan*
opserv_add_routing_plan(const char *name)
{
    struct routingPlan *rp;
    rp = calloc(1, sizeof(*rp));
    if (!rp)
        return NULL;
    if(dict_find(opserv_routing_plans, name, NULL))
        return NULL; /* plan already exists */
    rp->servers = dict_new();
    dict_set_free_data(rp->servers, free_routing_plan_server);

    dict_insert(opserv_routing_plans, strdup(name), rp);
    /* TODO: check for duplicate */
    return rp;
}

static void
free_routing_plan(void *data)
{
    struct routingPlan *rp = data;
    /* delete all the servers attached to this plan */
    dict_delete(rp->servers);
    /* free the plan struct */
    free(rp);
}

/*************************************************
* Functions to handle the active routing struct */

struct routeList 
*find_routeList_server(struct route *route, const char *server)
{
    struct routeList *rptr;
    if(!server)
        return(NULL);
    for(rptr = route->servers;rptr;rptr=rptr->next) {
        if(!strcasecmp(rptr->server, server))
            return(rptr);
    }
    return(NULL);
}

/* Wipes out the routing structure, freeing properly.
 * note: does NOT free itself, we just re-use it usually.*/
void 
wipe_route_list(struct route *route) {
    struct routeList *nextptr, *rptr;
    if(!route)
        return;
    for(rptr = opserv_route->servers; rptr; rptr=nextptr)
    {
        nextptr = rptr->next;
        free(rptr->server);
        if(rptr->uplink)
            free(rptr->uplink);
        if(rptr->secondaryuplink)
            free(rptr->secondaryuplink);
        free(rptr);
    }
    route->centered = true;
    route->count = 0;
    route->maxdepth = 0;
    route->servers = NULL;
}


int
rank_outside_rec(struct route *route, char *server, int count)
{
    struct routeList *rptr;
    int n, max = 0;
    int i = 0;
    if(count > 256) { /* XXX: 256 becomes max # of servers this works with, whats the real #? */
        return -1;
    }
    for(rptr = route->servers; rptr; rptr = rptr->next) {
        i++;
        if(!strcasecmp(server, rptr->uplink)) {
            log_module(MAIN_LOG, LOG_DEBUG, "%d:%d: rank_outside_rec(%s) calling rank_outside_rec(%s)", count, i, rptr->server, rptr->uplink);
            n = rank_outside_rec(route, rptr->server, count +1);
            if(n < 0) /* handle error condition */
                return n;
            if(n > max)
                max = n;
        }
    }
    if((rptr = find_routeList_server(route, server))) {
        rptr->outsideness = max;
        return(max + 1);
    }
    else {
        log_module(MAIN_LOG, LOG_WARNING, "routing struct rank_outsideness() couldnt find %s", server);
        return 0;
    }
}

int
rank_outsideness(struct route *route) 
{
    log_module(MAIN_LOG, LOG_DEBUG, "rank_outsideness(): Running...");
    route->maxdepth = rank_outside_rec(route, self->uplink->name, 0) - 1;
    if(route->maxdepth < 0) { /* if the rank failed, remove route */
        log_module(MAIN_LOG, LOG_WARNING, "The active routing plan has a loop! auto routing disabled.");
        wipe_route_list(route);
        return false;
    }
    return true;
}


/* Add servers to the routing structure */
void 
add_routestruct_server(struct route *route, const char *server, unsigned int port, char *uplink, char *secondary)
{
    struct routeList *rptr;
    char *hname;
    if(find_routeList_server(route, server))
    { 
        log_module(MAIN_LOG, LOG_WARNING, "Routing structure add server Skipping duplicate [%s]. This should never really be possible.", server);
        return;
    }
    rptr = calloc(1, sizeof(*rptr));
    rptr->server = strdup(server);
    rptr->port = port;
    if(!uplink) {
        hname = conf_get_data("server/hostname", RECDB_QSTRING);
        uplink = hname;
    }
    rptr->uplink = strdup(uplink);
    if(secondary)
        rptr->secondaryuplink = strdup(secondary);
    /* tack this server on the front of the list */
    rptr->next = route->servers;
    route->servers = rptr;
    route->count++;

#ifdef notdef /* I dont quite get this. there could be uncentered things 
               * added after our own uplink, and this function doesnt center
               * as it adds. -Rubin */
    /* If the map hasnt been centered yet... */
    if(route->centered == false) {
        /* AND we just added our own uplink to it... */
        if(!strcasecmp(server, self->uplink->name)) {
            change_route_uplinks(route); /* recenter it, n mark it centered. */
        }
    }
#endif
}

/* Recenter the routing struct around our current uplink */
int
change_route_uplinks(struct route *route)
{
    struct routeList *rptr;
    char lastserver[MAXLEN];
    char nextserver[MAXLEN];

    if(!route->servers)
        return false; /* no map to recenter */
    log_module(MAIN_LOG, LOG_DEBUG, "change_route_uplinks(): running...");
    char *servicename = conf_get_data("server/hostname", RECDB_QSTRING);
    strcpy(lastserver, servicename);
    rptr = find_routeList_server(route, self->uplink->name);
    if(!rptr) {
        log_module(MAIN_LOG, LOG_WARNING, "Cannot convert routing map to center: My uplink is not on the map! Marking map as uncentered.");
        route->centered = false;
        return false;
    }
    if(!strcasecmp(rptr->uplink, servicename)) {
        log_module(MAIN_LOG, LOG_DEBUG, "Already centered");
    }
    else { /* else, center it */
        while(rptr) {
            strcpy(nextserver, rptr->uplink);
            log_module(MAIN_LOG, LOG_DEBUG, "change_route_uplinks() changing %s uplink to %s.", rptr->server, lastserver);
            free(rptr->uplink);
            rptr->uplink = strdup(lastserver);
            strcpy(lastserver, rptr->server);
            rptr = find_routeList_server(route, nextserver);
        }
    }
    if(rank_outsideness(route) > 0) {
        route->centered = true;
        return true;
    }
    else
        return false;
}

int 
activate_routing(struct svccmd *cmd, struct userNode *user, char *plan_name)
{
    static struct routingPlan *rp;
    dict_iterator_t it;
    char *karma;

    if(plan_name) { /* make this the new active plan */
        if(!strcmp(plan_name, "*")) {
            /* disable routing */
            dict_remove(opserv_routing_plan_options, "ACTIVE");
            plan_name = NULL;
        }
        else {
            rp = dict_find(opserv_routing_plans, plan_name, NULL);
            if(!rp) {
                if(cmd && user)
                    reply("OSMSG_PLAN_NOT_FOUND", plan_name);
                else {
                    /* since it doesnt exist, remove the active setting */
                    dict_remove(opserv_routing_plan_options, plan_name);
                }
                log_module(MAIN_LOG, LOG_WARNING, "activate_routing() couldnt find active routing plan!");
                return 0;
            }
        }
    }
    else { /* find the active plan in settings */
        plan_name = dict_find(opserv_routing_plan_options, "ACTIVE", NULL);
    }
    if(!plan_name) { /* deactivated, or no plan was set active */
        /* TODO: delete routing map if it exists */
        wipe_route_list(opserv_route);
        return 1;
    }

    karma = dict_find(opserv_routing_plan_options, "KARMA", NULL);

    rp = dict_find(opserv_routing_plans, plan_name, NULL);

    /* this should really be done during opserv init */
    if(!opserv_route)
        opserv_route = calloc(1, sizeof(*opserv_route));

    /* Delete the existing active route */
    wipe_route_list(opserv_route);

    if(!rp || !rp->servers)
       return 1;
    for(it = dict_first(rp->servers); it; it = iter_next(it)) {
            const char* servername = iter_key(it);
            struct routingPlanServer *rps = iter_data(it), 
                                     *rp_uplink, *rp_second = NULL;
            char *uplink = rps->uplink;
            rp_uplink = dict_find(rp->servers, rps->uplink, NULL);
            if(rps->secondaryuplink)
                rp_second = dict_find(rp->servers, rps->secondaryuplink, NULL);

            /* If the normal uplink has bad karma, don't use it as a hub,
             * switch to the secondary uplink.
             */
            if(karma && enabled_string(karma) && rp_uplink && rp_uplink->karma < 0) {
                if(rps->secondaryuplink) {
                    uplink = rps->secondaryuplink;
                    /* unless the secondary uplinks karma is worse than the uplink. */
                    if((rp_second = dict_find(rp->servers, uplink, NULL)) && rp_second->karma < rp_uplink->karma)
                        uplink = rps->uplink;
                }
            }
            /*
             * If _WE_ have bad karma, don't link us to our normal uplink, maybe
             * its a bad route. switch to secondary. Important: dont neg karma when we arnt on
             * our primary uplink, or we'll get stuck on secondary when THAT link is worse.
             */
            if(karma && enabled_string(karma) && (rps->karma < 0 || rps->offline) ) {
                    if(rps->secondaryuplink) {
                        uplink = rps->secondaryuplink;
                    }
            }
            log_module(MAIN_LOG, LOG_DEBUG, "activate_routing() adding %s:%d %s", servername, rps->port, uplink);
            add_routestruct_server(opserv_route, servername, rps->port, uplink, NULL);
    }
    if(change_route_uplinks(opserv_route))
    {
        return 1;
    }
    else if(user) {
        reply("OSMSG_ROUTING_ACTIVATION_ERROR");
        activate_routing(cmd, user, "*");
        return 0;
    }
    /* routing activation failed but we dont do anything? */
    return 1;
}


void routing_init()
{
    activate_routing(NULL, NULL, NULL);

    /* start auto-routing system */
    reroute_timer_reset(0); 
}

/*******************************************************
 * Functions to handle online route configuration via opserv
 */
static void route_show_option(struct svccmd *cmd, struct userNode *user, char *name)
{
    char *value = dict_find(opserv_routing_plan_options, name, NULL);
    if(value) {
        if(!strcmp("RETRY_PERIOD", name)) { /* Show as an interval */
            char buff[INTERVALLEN+1];
            reply("OSMSG_ROUTINGPLAN_OPTION", name, intervalString(buff, atoi(value), user->handle_info));
        }
        else if(!strcmp("ACTIVE", name)) { 
            if(opserv_route && opserv_route->servers)
                reply("OSMSG_ROUTINGPLAN_ACTIVE", value);
            else
                reply("OSMSG_ROUTINGPLAN_OPTION_NOT_SET", name);
        }
        else {
            reply("OSMSG_ROUTINGPLAN_OPTION", name, value);
        }
    }
    else {
        reply("OSMSG_ROUTINGPLAN_OPTION_NOT_SET", name);
    }
}

static void route_show_options(struct svccmd *cmd, struct userNode *user)
{
    char *options[] = {"ACTIVE", "RETRY_PERIOD", "CONN_PINGOUT", "CONN_READERROR", "KARMA", "DEFAULT_PORT", NULL};
    int i;
    for(i = 0; options[i]; i++) {
        route_show_option(cmd, user, options[i]);
    }
}

/* called from timeq */
void routing_connect_timeout(void *data)
{
    struct waitingConnection *wc = data;
    struct server *target = GetServerH(wc->target);
    if(!target) {
        dict_remove(opserv_waiting_connections, wc->server);
        return; /* server we wanted to connect new server to is gone, just give up */
    }
    routing_handle_connect_failure(target, wc->server, "Connection timed out");
    /* the following invalidates server variable! */
    dict_remove(opserv_waiting_connections, wc->server);
}

void routing_delete_connect_timer(char *server)
{
    struct waitingConnection *wc = dict_find(opserv_waiting_connections, server, 0);
    if(wc) {
        timeq_del(0, routing_connect_timeout, wc, TIMEQ_IGNORE_WHEN);
        dict_remove(opserv_waiting_connections, server);
    }
}


void
routing_connect_server(char *server, int port, struct server *to)
{
    struct waitingConnection *wc = calloc(sizeof(*wc), 1);

    wc->server = strdup(server);
    wc->target = strdup(to->name);
    /* Just to make sure there isn't one left hanging
     * if 2 connections are attempted at once.. 
     * */
    routing_delete_connect_timer(server);
    dict_insert(opserv_waiting_connections, strdup(server), wc);
    timeq_add(now + ROUTING_CONNECT_TIMEOUT, routing_connect_timeout, wc);

    irc_connect(opserv, server, port, to);
}

int 
routing_connect_one(struct route *route, char *server)
{
    struct routeList *rptr;
    struct server *sptr, *suptr;
    for(rptr = route->servers; rptr; rptr = rptr->next) {
        if(!strcasecmp(rptr->server, server)) {
            /* this is the one, connect it */
            suptr = GetServerH(rptr->uplink);
            sptr = GetServerH(rptr->server);
            if(sptr)
                return 1; /* already linked */
            if(suptr) {
                routing_connect_server(rptr->server, rptr->port, suptr);
                return 1; /* attempted link */
            }
            return 0; /* its uplink isnt here to link to */
        }
    }
    log_module(MAIN_LOG, LOG_DEBUG, "Tried to link %s but its not in the active routing struct!", server);
    return 0; /* server wasnt found in active route struct. */
}

int routing_connect_children(struct route *route, char *server)
{
    struct routeList *rptr;
    struct server *sptr, *suptr;
    for(rptr = route->servers; rptr; rptr = rptr->next) {
        if(!strcasecmp(rptr->uplink, server)) {
            /* this is the one, connect it */
            suptr = GetServerH(rptr->uplink);
            sptr = GetServerH(rptr->server);
            if(sptr)
                continue; /* already linked */
            if(suptr) {
                routing_connect_server(rptr->server, rptr->port, suptr);
                continue; /* attempted link */
            }
            continue; /* its uplink isnt here to link to */
        }
    }
    return 1; /* server wasnt found in active route struct ?! */
}

int reroute(struct route *route, struct userNode *user, struct svccmd *cmd, char *directive)
{
    struct routeList *rptr;
    struct server *sptr, *suptr;
    int connect = 0, move = 0, missing = 0, i;
    char d = toupper(*directive);

    if(!route || !route->servers) {
        reply("OSMSG_REROUTING_NOTCONFIGURED");
        return 0;
    }
    if(user) {
        if(d == 'N') { /* normal */
            irc_wallops("%s", "Attempting a reroute of the network according to loaded map...");
            reply("OSMSG_REROUTING_ACC_MAP");
        }
        else if(d == 'C') { /* only connect */
            reply("OSMSG_CONNECTING_MISSING_ONLY");
        }
        else if(d == 'T') { /* test */
            reply("OSMSG_TESTING_REROUTE");
        }
        else
        {
            reply("OSMSG_INVALID_DIRECTIVE", directive);
            return 0;
        }
    }
    for(i = 0; i <= route->maxdepth-1; i++) {
        for(rptr = route->servers; rptr; rptr = rptr->next) {
            if(rptr->outsideness == i) {
                /*  debugging */
                if(user && d=='T')
                    reply("OSMSG_INSPECTING_SERVER", rptr->server);
                suptr = GetServerH(rptr->uplink);
                if(!suptr) {
                    if(rptr->secondaryuplink && (suptr = GetServerH(rptr->secondaryuplink))) {
                        if(user)
                            reply("OSMSG_COULDNT_FIND_SERVER", rptr->uplink, rptr->secondaryuplink, rptr->server);
                    }
                }
                if(suptr) { /* if the proper uplink is connected.. */
                    sptr = GetServerH(rptr->server);
                    if(d == 'C' && sptr) {
                        continue; /* Already linked */
                    }
                    /* If server is missing or the uplinks are not the same then... */
                    else if(!sptr ||  strcasecmp(sptr->uplink->name, rptr->uplink)) {
                        if(!sptr) {
                            connect++;
                        }
                        else { /* Server is already connected somewhere */
                            if(strcasecmp(sptr->uplink->name, rptr->uplink)) {
                                if(d != 'T') {  /* do it for real */
                                    irc_squit_route(sptr, "%s issued reroute.", user ? user->nick : opserv->nick);
                                }
                                else {  /* just pretend */
                                    reply("OSMSG_SQUIT", rptr->server);
                                }
                                move++;
                            }
                        }
                        if(d != 'T')  /* do the real thing */
                            routing_connect_server(rptr->server, rptr->port, suptr);
                        else /* just pretend */
                            reply("OSMSG_CONNECT", rptr->server, rptr->port, suptr->name);
                    }
                }
                else {
                    log_module(MAIN_LOG, LOG_DEBUG, "server uplink %s was not found, cant connect %s", rptr->uplink, rptr->server);
                    missing++;
                }
            } /* outsideness = 1 */
        } /* rptr */
    } /* maxdepth */
    if(user) { /* report on what we did */
        if(!strcasecmp(directive, "C")) {
            if(connect > 0)
                reply("OSMSG_CONNECTING_MISSING", connect);
            else
                reply("OSMSG_NO_SERVERS_MISSING");
        }
        else {
            if(move+connect > 0)
                reply("OSMSG_REROUTE_COMPLETE", move, connect, move+connect);
            else
                reply("OSMSG_NO_ROUTING_NECESSARY");
            if(missing > 0)
                reply("OSMSG_UPLINKS_MISSING", missing);
        }
    }
    return(move+connect);
}

static MODCMD_FUNC(cmd_reroute) {
    char* upper;
    upper = argv[1];
    if(reroute(opserv_route, user, cmd, upper))
        return 1;
    else
        return 0;
}

/* reroute_timer(run)
 * run - if it is null, just setup the timer
 * but dont run reroute now. otherwise reroute 
 * and setup timer.
 */
void reroute_timer(void *data) {
    /* Delete any other timers such as this one.. */
    timeq_del(0, reroute_timer, NULL, TIMEQ_IGNORE_DATA | TIMEQ_IGNORE_WHEN);

    if(!opserv_route || !opserv_route->servers) 
        return; /* no active route */
    char *retry_period = dict_find(opserv_routing_plan_options, "RETRY_PERIOD", NULL);
    if(!retry_period)
        return; /* retry_period invalid */
    unsigned int freq = atoi(retry_period);
    if(freq < 1) 
        return; /* retry_period set to 0, disable */

    /* opserv_debug("Reroute timer checking reroute"); */
    log_module(MAIN_LOG, LOG_DEBUG, "Reroute timer checking reroute()");

    /* Do the reroute C attempt */
    if(data)
        reroute(opserv_route, NULL, NULL, "C");

    /* Re-add ourselves to the timer queue */
    timeq_add(now + freq, reroute_timer, "run");
}

void routing_change_karma(struct routingPlanServer *rps, const char *server, int change) {

    int oldkarma = rps->karma;
    rps->karma += change;
    if(rps->karma < KARMA_MIN)
        rps->karma = KARMA_MIN;
    if(rps->karma > KARMA_MAX)
        rps->karma = KARMA_MAX;
    log_module(MAIN_LOG, LOG_DEBUG, "Changing %s karma by %d. new karma %d.", server, change, rps->karma);
    if(oldkarma > 0 && rps->karma < 0) {
        /* we just crossed over to negitive */
        log_module(MAIN_LOG, LOG_INFO, "Server %s just went negitive karma!", server);
        activate_routing(NULL, NULL, NULL);
    }
    else if(oldkarma < 0 && rps->karma > 0) {
        /* we just crossed over to positive */
        log_module(MAIN_LOG, LOG_INFO, "Server %s just went back positive karma.", server);
        activate_routing(NULL, NULL, NULL);
    }
}

void routing_karma_timer(void *data) {
    time_t next;
    time_t timer_init = data ? atoi(data) : 0;
    char buf[MAXLEN];

    log_module(MAIN_LOG, LOG_DEBUG, "routing_karma_timer() is running. timer_init=%d.", (unsigned int) timer_init);

    /* If theres a time passed in, dont run unless that time is overdue. */
    if(!timer_init || (timer_init < now)) {
        if(opserv_route && opserv_route->servers) {
            char *active = dict_find(opserv_routing_plan_options, "ACTIVE", NULL);
            struct routingPlan *rp;
            if(active && (rp = dict_find(opserv_routing_plans, active, NULL))) {
                dict_iterator_t it;
                /* Walk through each server in the active routing plan.. */
                for(it = dict_first(rp->servers); it; it = iter_next(it)) {
                    struct routingPlanServer *rps = iter_data(it);
                    struct server *server = GetServerH(iter_key(it));
                    /* Give everyone +KARMA_ENTROPE just for nothing */
                    routing_change_karma(rps, iter_key(it), KARMA_ENTROPE);
                    /* give an additonal +KARMA_RELIABLE to servers that
                     * have been linked at least KARMA_TIMER seconds. */
                    if(server  && (server->link < (now - KARMA_TIMER) ) ) {
                            routing_change_karma(rps, iter_key(it), KARMA_RELIABLE);
                    }
                }
            }
        }
    }
    if(timer_init > now)  /* loading a saved value */
        next = timer_init;
    else /* no scheduled timer, or we missed it. start from now */
        next = now + KARMA_TIMER;
    /* Save when karma_timer should run again in case we restart before then */
    log_module(MAIN_LOG, LOG_DEBUG, "routing_karma_timer() scheduling self to run again at %d", (unsigned int) next);
    sprintf(buf, "%u", (unsigned int) next);
    dict_insert(opserv_routing_plan_options, "KARMA_TIMER", strdup(buf));
    /* add a timer to run this again .. */
    timeq_add(next, routing_karma_timer, NULL);
}

void routing_handle_neg_karma(char *server, char *uplink, int change)
{
    /* if server's primary uplink is uplink, OR, uplink's primary uplink is server,
     * then whichever one, gets its karma changed. */
    char *active = dict_find(opserv_routing_plan_options, "ACTIVE", NULL);
    struct routingPlan *rp;
    struct routingPlanServer *rps;
    if(!active)
        return;
    if(!(rp = dict_find(opserv_routing_plans, active, NULL)))
        return;
    if((rps = dict_find(rp->servers, server, NULL))) {
        if(!strcasecmp(rps->uplink, uplink)) {
            /* server's uplink is uplink */
            routing_change_karma(rps, server, change);
            return;
        }
    }
    if((rps = dict_find(rp->servers, uplink, NULL))) {
        if(!strcasecmp(rps->uplink, server)) {
            /* uplink's uplink is server */
            routing_change_karma(rps, uplink, change);
            return;
        }
    }
}

void
routing_handle_squit(char *server, char *uplink, char *message)
{
    log_module(MAIN_LOG, LOG_DEBUG, "Routing_handle_squit(%s, %s)", server, message);

    char *val;

    if(match_ircglob(message, "Ping timeout")) {
        routing_handle_neg_karma(server, uplink, KARMA_PINGOUT);
        /* if conn_pingout is true, try to reconnect it obaying karma rules. */

        val = dict_find(opserv_routing_plan_options, "CONN_PINGOUT", 0);
        if(val && enabled_string(val))
            routing_connect_one(opserv_route, server);
    }
    else if(match_ircglob(message, "Read error:*")) {
        routing_handle_neg_karma(server, uplink, KARMA_READERROR);
        /* if conn_readerror is true, try to reconnect it obaying karma rules. */
        val = dict_find(opserv_routing_plan_options, "CONN_READERROR", 0);
        if(val && enabled_string(val))
            routing_connect_one(opserv_route, server);
    }
    /* Else whats the message (an oper squit it?) dont interfere */
}

void
routing_handle_connect(char *server, char *uplink)
{
    char *active;
    struct routingPlan *rp;
    struct routingPlanServer *rps;
    dict_iterator_t it;

    log_module(MAIN_LOG, LOG_DEBUG, "routing_handle_connect(%s, %s)", server, uplink);
    /* delete a pending connection timer, if any */
    routing_delete_connect_timer(server);
    /* check if routing is active... */
    active = dict_find(opserv_routing_plan_options, "ACTIVE", NULL);
    if(!active)
        return;
    rp = dict_find(opserv_routing_plans, active, NULL);
    if(!rp)
        return;

    /* If its offline, mark it online again.. */
    if((rps = dict_find(rp->servers, server, NULL))) {
        if(rps->offline == true) {
            rps->offline = false;
            if(rps->secondaryuplink) {
                /* re-activate to move it back to its primary */
                activate_routing(NULL, NULL, NULL);
            }
        }
        /* if there are any servers missing who have this server as uplink try to connect them.  */
        routing_connect_children(opserv_route, server);
    }
    /* foreach server x3 knows about, if the uplink is this server, call this function on the child. */
    for (it=dict_first(servers); it; it=iter_next(it)) {
        struct server *sptr = iter_data(it);
        if(sptr && sptr->uplink && !strcasecmp(server, sptr->uplink->name)) {
            log_module(MAIN_LOG, LOG_DEBUG, "routing_handle_connect calling self on %s's leaf %s", server, sptr->name);
            routing_handle_connect(sptr->name, sptr->uplink->name);
        }
    }
}

/* Handle a failed attempt at connecting servers
 *  - we should only get here regarding servers X3 attempted to link, other
 *  opers link messages go to them not to us
 */
void
routing_handle_connect_failure(struct server *source, char *server, char *message)
{
    char *active;
    struct routingPlan *rp;
    struct routingPlanServer *rps;
    log_module(MAIN_LOG, LOG_WARNING, "Failed to connect %s to %s: %s", server, source->name, message);
    /* remove the waiting connection n timeq */
    routing_delete_connect_timer(server);
    /* check if routing is active.. */
    active = dict_find(opserv_routing_plan_options, "ACTIVE", NULL);
    if(!active)
        return;
    rp = dict_find(opserv_routing_plans, active, NULL);
    if(!rp)
        return;

    if( ((rps = dict_find(rp->servers, server, NULL)) && !strcasecmp(rps->uplink, source->name))) {
        /* failed to connect to its primary uplink */
        if(rps->offline == false) {
            rps->offline = true;
            if(rps->secondaryuplink) {
                /* re-activate routing so the secondary 
                 * becomes its uplink, and try again */
                activate_routing(NULL, NULL, NULL);
                /* attempt to link it again. */
                routing_connect_one(opserv_route, server); 
                /* TODO: reconnect any missing servers who
                 * normally connect to server, using their backups.
                 * Probably should just issue a reroute C here. */
            }
        }
    }
}

/* Delete any existing timers, and start the timer again 
 * using the passed time for the first run.
 * - this is called during a retry_period change
 *   before it has saved the new value. 
 *
 *   If time is 0, lookup the interval. */
void reroute_timer_reset(unsigned int time)
{
    timeq_del(0, reroute_timer, NULL, TIMEQ_IGNORE_DATA | TIMEQ_IGNORE_WHEN);
    if(time == 0) {
        if(!opserv_route || !opserv_route->servers)
            return; /* no active route */
        char *retry_period = dict_find(opserv_routing_plan_options, "RETRY_PERIOD", NULL);
        if(!retry_period)
            return; /* retry_period invalid */
        time = atoi(retry_period);
        if(time < 1)
            return; /* retry_period set to 0, disable */

    }
    timeq_add(now + time, reroute_timer, "run");
}

static MODCMD_FUNC(cmd_routing_set)
{
    char *option = argv[1];
    char *options[] = {"ACTIVE", "RETRY_PERIOD", "CONN_PINGOUT", "CONN_READERROR", "KARMA", "DEFAULT_PORT", NULL};
    int i;
    if(argc < 2) {
        route_show_options(cmd, user);
    }
    else {
        char *found_option = NULL;
        for(i = 0; options[i]; i++) {
            if(!strcasecmp(options[i], option))
                found_option = options[i];
        }
        if(!found_option) {
            reply("OSMSG_ROUTINGPLAN_OPTION_NOT_FOUND", option);
            return 0;
        }
        if(argc > 2) {
            char *value   = argv[2];
            char buff[MAXLEN]; /* whats the max length of unsigned int as printf'd? */
            if(!strcmp(found_option, "ACTIVE")) { /* must be an existing route. */
                if(disabled_string(value) || false_string(value)) {
                    /* make none of the maps active */
                    activate_routing(cmd, user, "*");
                    reply("OSMSG_ROUTING_DISABLED");
                    return 1;
                }
                else if(!activate_routing(cmd, user, value)) {
                    /* neg reply handled in activate_routing */
                    return 0;
                }
            }
            if(!strcmp(found_option, "CONN_READERROR") || !strcmp(found_option, "CONN_PINGOUT") ||
               !strcmp(found_option, "KARMA") ) {
                if( enabled_string(value)) {
                    value = "ENABLED";
                }
                else if( disabled_string(value) ) {
                    value = "DISABLED";
                }
                else {
                    reply("MSG_INVALID_BINARY", value);
                    return 0;
                }
            }
            if(!strcmp(found_option, "RETRY_PERIOD")) {
                unsigned int duration = ParseInterval(value);
                sprintf(buff, "%d", duration);
                value = buff;
                reroute_timer_reset(duration);
            }
            /* set the value here */
            dict_remove(opserv_routing_plan_options, found_option);
            dict_insert(opserv_routing_plan_options, strdup(found_option), strdup(value));
            route_show_option(cmd, user, found_option);
        }
        else {
            /* show the current value */
            route_show_option(cmd, user, found_option);
        }
    }
    return 1;
}

static MODCMD_FUNC(cmd_stats_routing_plans) {
    dict_iterator_t rpit;
    dict_iterator_t it;
    struct routingPlan *rp;
    if(argc > 1) {
        reply("OSMSG_ROUTINGPLAN");
        reply("OSMSG_ROUTINGPLAN_BAR");
        for(rpit = dict_first(opserv_routing_plans); rpit; rpit = iter_next(rpit)) {
            const char* name = iter_key(rpit);
            rp = iter_data(rpit);
            if(match_ircglob(name, argv[1])) {
                reply("OSMSG_ROUTINGPLAN_NAME", name);
                for(it = dict_first(rp->servers); it; it = iter_next(it)) {
                    const char* servername = iter_key(it);
                    struct routingPlanServer *rps = iter_data(it);
                    reply("OSMSG_ROUTINGPLAN_SERVER", servername, rps->port, rps->uplink, rps->karma, rps->offline? "offline" : "online", rps->secondaryuplink ? rps->secondaryuplink : "None");
                }
            }

        }
        reply("OSMSG_ROUTINGPLAN_END");
    }
    else {
        reply("OSMSG_ROUTINGPLAN_LIST_HEAD");
        reply("OSMSG_ROUTINGPLAN_BAR");
        for(rpit = dict_first(opserv_routing_plans); rpit; rpit = iter_next(rpit)) {
            const char* name = iter_key(rpit);
            reply("OSMSG_ROUTINGPLAN_LIST", name);
        }
        reply("OSMSG_ROUTINGPLAN_END");
        route_show_options(cmd, user);
    }
    return 1;
}


static MODCMD_FUNC(cmd_routing_addplan)
{
    char *name;
    name = argv[1];
    /* dont allow things like 'off', 'false', '0' because thats how we disable routing. */
    if(*name && !disabled_string(name) && !false_string(name)) {
        if(opserv_add_routing_plan(name)) {
            reply("OSMSG_ADDPLAN_SUCCESS", name);
            return 1;
        }
        else {
            reply("OSMSG_ADDPLAN_FAILED", name);
            return 0;
        }
    }
    else
    {
        reply("OSMSG_INVALID_PLAN");
        return 0;
    }
}

static MODCMD_FUNC(cmd_routing_delplan)
{
    char *name = argv[1];
    if( dict_remove(opserv_routing_plans, name) ) {
        char *active = dict_find(opserv_routing_plan_options, "ACTIVE", NULL);
        if(active && !strcasecmp(active, name)) {
            /* if this was the active plan, disable routing */
            activate_routing(cmd, user, "*");
            reply("OSMSG_ROUTING_DISABLED");
        }
        reply("OSMSG_PLAN_DELETED");
        return 1;
    }
    else {
        reply("OSMSG_PLAN_NOT_FOUND", name);
        return 0;
    }
}

static MODCMD_FUNC(cmd_routing_addserver)
{
    char *plan;
    char *server;
    char *portstr;
    char *uplink;
    char *second;
    unsigned int port;
    struct routingPlan *rp;

    plan   = argv[1];
    server = strdup(argv[2]);
    server = strtok(server, ":");
    portstr = strtok(NULL, ":"); 
    if(portstr)
        port = atoi(portstr);
    else {
        char *str = dict_find(opserv_routing_plan_options, "DEFAULT_PORT", NULL);
        uplink = argv[3];
        port = str ? atoi(str) : 0;
    }
    uplink = argv[3];
    if(argc > 4)
        second = argv[4];
    else
        second = NULL;

    if( (rp = dict_find(opserv_routing_plans, plan, 0))) {
        char *active;
        opserv_routing_plan_add_server(rp, server, uplink, port, KARMA_DEFAULT, second, 0);
        reply("OSMSG_PLAN_SERVER_ADDED", server);
        if((active = dict_find(opserv_routing_plan_options, "ACTIVE", 0)) && !strcasecmp(plan, active)) {
            /* re-activate routing with new info */
            activate_routing(cmd, user, NULL);
        }
        
        free(server);
        return 1;
    }
    else {
        reply("OSMSG_PLAN_NOT_FOUND", plan);
        free(server);
        return 0;
    }
}

static MODCMD_FUNC(cmd_routing_delserver)
{
    char *plan;
    char *server;
    struct routingPlan *rp;
    plan = argv[1];
    server = argv[2];
    if( (rp = dict_find(opserv_routing_plans, plan, 0))) {
        if(dict_remove(rp->servers, server)) {
            char *active;
            reply("OSMSG_PLAN_SERVER_DELETED");
            if((active = dict_find(opserv_routing_plan_options, "ACTIVE", 0)) && !strcasecmp(plan, active)) {
                /* re-activate routing with new info */
                activate_routing(cmd, user, NULL);
            }

            return 1;
        }
        else {
            reply("OSMSG_PLAN_SERVER_NOT_FOUND", server);
            return 0;
        }
    }
    else {
        reply("OSMSG_PLAN_NOT_FOUND", plan);
        return 0;
    }
}


/*************************************************
 * Functions to deal with 'route map' command   */

/* Figures out how many downlinks there are for proper
 * drawing of the route map */
int 
num_route_downlinks(struct route *route, char *name)
{
    struct routeList *rptr;
    int num = 0;
    rptr = route->servers;
    while(rptr) {
        if(!strcasecmp(rptr->uplink, name))
            num++;
        rptr = rptr->next;
    }
    return num;
}

void
show_route_downlinks(struct svccmd *cmd, struct route *route, struct userNode *user, char *name, char *prevpre, char *arrowchar, int reset)
{
    struct routeList *servPtr;
    struct server *sptr;
    int j;
    char pre[MAXLEN];
    char *nextpre;
    char *status;
    int num = 0;
    static int depth = 0;

    if(reset)
        depth = 0;

    nextpre = malloc(MAXLEN);
    strcpy(pre, prevpre);

    sptr = GetServerH(name);
    if((servPtr = find_routeList_server(route, name))) {
        if(!sptr)
            status = " ";
        else if (!strcasecmp(sptr->uplink->name, servPtr->uplink))
            status = "X";
        else if(servPtr->secondaryuplink && !strcasecmp(sptr->name, servPtr->secondaryuplink))
            status = "/";
        else
            status = "!";
        reply("OSMSG_DOWNLINKS_FORMAT_A", pre, arrowchar, name, status);
    }
    else
        reply("OSMSG_DOWNLINKS_FORMAT_B", self->name);
    j = num_route_downlinks(route, name);
    servPtr = route->servers;
    while(servPtr) {
        if(!strcasecmp(servPtr->uplink, name)) {
            strcpy(nextpre, pre);
            if(depth++ > 0) {
                if(arrowchar[0] == '`')
                    strcat(nextpre, "  ");
                else
                    strcat(nextpre, "| ");
            }
            if(j > ++num) {
                show_route_downlinks(cmd, route, user, servPtr->server, nextpre, "|", 0);
            }
            else {
                show_route_downlinks(cmd, route, user, servPtr->server, nextpre, "`", 0);
            }
        }
        servPtr = servPtr->next;
    }
    free(nextpre);
}

int
show_route_map(struct route *route, struct userNode *user, struct svccmd *cmd)
{
    if(!route || !route->servers) {
        reply("OSMSG_ROUTELIST_EMPTY");
        return 0;
    }

    char *serviceName = conf_get_data("server/hostname", RECDB_QSTRING);
    reply("OSMSG_ROUTELIST_AS_PLANNED");
    show_route_downlinks(cmd, route, user, serviceName, "", "`", 1);
    reply("OSMSG_MAP_CENTERED", route->centered ? "is" : "is not", route->maxdepth);
    return 1;
}

static MODCMD_FUNC(cmd_routing_map)
{
    show_route_map(opserv_route, user, cmd);
    return 1;
}




/* End of auto routing functions *
 *********************************/
   
static MODCMD_FUNC(cmd_addbad)
{
    unsigned int arg, count;
    dict_iterator_t it;
    int bad_found, exempt_found;

    /* Create the bad word if it doesn't exist. */
    bad_found = !opserv_add_bad_word(cmd, user, argv[1]);

    /* Look for exception modifiers. */
    for (arg=2; arg<argc; arg++) {
        if (!irccasecmp(argv[arg], "except")) {
            reply("MSG_DEPRECATED_COMMAND", "addbad ... except", "addexempt");
            if (++arg > argc) {
                reply("MSG_MISSING_PARAMS", "except");
                break;
            }
            for (count = 0; (arg < argc) && IsChannelName(argv[arg]); arg++) {
                dict_find(opserv_exempt_channels, argv[arg], &exempt_found);
                if (!exempt_found) {
                    dict_insert(opserv_exempt_channels, strdup(argv[arg]), NULL);
                    count++;
                }
            }
            reply("OSMSG_ADDED_EXEMPTIONS", count);
        } else {
            reply("MSG_DEPRECATED_COMMAND", "addbad (with modifiers)", "addbad");
            reply("OSMSG_BAD_MODIFIER", argv[arg]);
        }
    }

    /* Scan for existing channels that match the new bad word. */
    if (!bad_found) {
        for (it = dict_first(channels); it; it = iter_next(it)) {
            struct chanNode *channel = iter_data(it);

            if (!opserv_bad_channel(channel->name))
                continue;
            channel->bad_channel = 1;
            if (channel->name[0] == '#')
                opserv_shutdown_channel(channel, "OSMSG_ILLEGAL_REASON");
            else {
                unsigned int nn;
                for (nn=0; nn<channel->members.used; nn++) {
                    struct userNode *user = channel->members.list[nn]->user;
                    DelUser(user, cmd->parent->bot, 1, "OSMSG_ILLEGAL_KILL_REASON");
                }
            }
        }
    }

    return 1;
}

static MODCMD_FUNC(cmd_delbad)
{
    dict_iterator_t it;
    unsigned int nn;

    for (nn=0; nn<opserv_bad_words->used; nn++) {
        if (!irccasecmp(opserv_bad_words->list[nn], argv[1])) {
            string_list_delete(opserv_bad_words, nn);
            for (it = dict_first(channels); it; it = iter_next(it)) {
                channel = iter_data(it);
                if (irccasestr(channel->name, argv[1])
                    && !opserv_bad_channel(channel->name)) {
                    DelChannelUser(cmd->parent->bot, channel, "Channel name no longer contains a bad word.", 1);
                    timeq_del(0, opserv_part_channel, channel, TIMEQ_IGNORE_WHEN);
                    channel->bad_channel = 0;
                }
            }
            reply("OSMSG_REMOVED_BAD", argv[1]);
            return 1;
        }
    }
    reply("OSMSG_NOT_BAD_WORD", argv[1]);
    return 0;
}

static MODCMD_FUNC(cmd_addexempt)
{
    const char *chanName;

    if ((argc > 1) && IsChannelName(argv[1])) {
        chanName = argv[1];
    } else {
        reply("MSG_NOT_CHANNEL_NAME");
        OPSERV_SYNTAX();
        return 0;
    }
    dict_insert(opserv_exempt_channels, strdup(chanName), NULL);
    channel = GetChannel(chanName);
    if (channel) {
        if (channel->bad_channel) {
            DelChannelUser(cmd->parent->bot, channel, "Channel is now exempt from bad-word checking.", 1);
            timeq_del(0, opserv_part_channel, channel, TIMEQ_IGNORE_WHEN);
        }
        channel->bad_channel = 0;
    }
    reply("OSMSG_ADDED_EXEMPTION", chanName);
    return 1;
}

static MODCMD_FUNC(cmd_delexempt)
{
    const char *chanName;

    if ((argc > 1) && IsChannelName(argv[1])) {
        chanName = argv[1];
    } else {
        reply("MSG_NOT_CHANNEL_NAME");
        OPSERV_SYNTAX();
        return 0;
    }
    if (!dict_remove(opserv_exempt_channels, chanName)) {
        reply("OSMSG_NOT_EXEMPT", chanName);
        return 0;
    }
    reply("OSMSG_REMOVED_EXEMPTION", chanName);
    return 1;
}

static void
opserv_expire_trusted_host(void *data)
{
    struct trusted_host *th = data;
    dict_remove(opserv_trusted_hosts, th->ipaddr);
}

static void
opserv_add_trusted_host(const char *ipaddr, unsigned int limit, const char *issuer, time_t issued, time_t expires, const char *reason)
{
    struct trusted_host *th;
    th = calloc(1, sizeof(*th));
    if (!th)
        return;
    th->ipaddr = strdup(ipaddr);
    th->reason = reason ? strdup(reason) : NULL;
    th->issuer = issuer ? strdup(issuer) : NULL;
    th->issued = issued;
    th->limit = limit;
    th->expires = expires;
    dict_insert(opserv_trusted_hosts, th->ipaddr, th);
    if (th->expires)
        timeq_add(th->expires, opserv_expire_trusted_host, th);
}

static void
free_trusted_host(void *data)
{
    struct trusted_host *th = data;
    free(th->ipaddr);
    free(th->reason);
    free(th->issuer);
    free(th);
}

static MODCMD_FUNC(cmd_addtrust)
{
    unsigned long interval;
    char *reason, *tmp;
    irc_in_addr_t tmpaddr;
    unsigned int count;

    if (dict_find(opserv_trusted_hosts, argv[1], NULL)) {
        reply("OSMSG_ALREADY_TRUSTED", argv[1]);
        return 0;
    }

    if (!irc_pton(&tmpaddr, NULL, argv[1])) {
        reply("OSMSG_BAD_IP", argv[1]);
        return 0;
    }

    count = strtoul(argv[2], &tmp, 10);
    if (*tmp != '\0') {
        reply("OSMSG_BAD_NUMBER", argv[2]);
        return 0;
    }

    interval = ParseInterval(argv[3]);
    if (!interval && strcmp(argv[3], "0")) {
        reply("MSG_INVALID_DURATION", argv[3]);
        return 0;
    }

    reason = unsplit_string(argv+4, argc-4, NULL);
    opserv_add_trusted_host(argv[1], count, user->handle_info->handle, now, interval ? (now + interval) : 0, reason);
    reply("OSMSG_ADDED_TRUSTED");
    return 1;
}

static MODCMD_FUNC(cmd_edittrust)
{
    unsigned long interval;
    struct trusted_host *th;
    char *reason, *tmp;
    unsigned int count;

    th = dict_find(opserv_trusted_hosts, argv[1], NULL);
    if (!th) {
        reply("OSMSG_NOT_TRUSTED", argv[1]);
        return 0;
    }
    count = strtoul(argv[2], &tmp, 10);
    if (!count || *tmp) {
        reply("OSMSG_BAD_NUMBER", argv[2]);
        return 0;
    }
    interval = ParseInterval(argv[3]);
    if (!interval && strcmp(argv[3], "0")) {
        reply("MSG_INVALID_DURATION", argv[3]);
        return 0;
    }
    reason = unsplit_string(argv+4, argc-4, NULL);
    if (th->expires)
        timeq_del(th->expires, opserv_expire_trusted_host, th, 0);

    free(th->reason);
    th->reason = strdup(reason);
    free(th->issuer);
    th->issuer = strdup(user->handle_info->handle);
    th->issued = now;
    th->limit = count;
    if (interval) {
        th->expires = now + interval;
        timeq_add(th->expires, opserv_expire_trusted_host, th);
    } else
        th->expires = 0;
    reply("OSMSG_UPDATED_TRUSTED", th->ipaddr);
    return 1;
}

static MODCMD_FUNC(cmd_deltrust)
{
    unsigned int n;

    for (n=1; n<argc; n++) {
        struct trusted_host *th = dict_find(opserv_trusted_hosts, argv[n], NULL);
        if (!th)
            continue;
        if (th->expires)
            timeq_del(th->expires, opserv_expire_trusted_host, th, 0);
        dict_remove(opserv_trusted_hosts, argv[n]);
    }
    reply("OSMSG_REMOVED_TRUSTED");
    return 1;
}

/* This doesn't use dict_t because it's a little simpler to open-code the
 * comparisons (and simpler arg-passing for the ADD subcommand).
 */
static MODCMD_FUNC(cmd_clone)
{
    int i;
    struct userNode *clone;

    clone = GetUserH(argv[2]);
    if (!irccasecmp(argv[1], "ADD")) {
        char *userinfo;
        char ident[USERLEN+1];

        if (argc < 5) {
            reply("MSG_MISSING_PARAMS", argv[1]);
            OPSERV_SYNTAX();
            return 0;
        }
        if (clone) {
            reply("OSMSG_CLONE_EXISTS", argv[2]);
            return 0;
        }
        userinfo = unsplit_string(argv+4, argc-4, NULL);
        for (i=0; argv[3][i] && (i<USERLEN); i++) {
            if (argv[3][i] == '@') {
                ident[i++] = 0;
                break;
            } else {
                ident[i] = argv[3][i];
            }
        }
        if (!argv[3][i] || (i==USERLEN)) {
            reply("OSMSG_NOT_A_HOSTMASK");
            return 0;
        }
        if (!(clone = AddClone(argv[2], ident, argv[3]+i, userinfo))) {
            reply("OSMSG_CLONE_FAILED", argv[2]);
            return 0;
        }
        reply("OSMSG_CLONE_ADDED", clone->nick);
        return 1;
    }
    if (!clone) {
        reply("MSG_NICK_UNKNOWN", argv[2]);
        return 0;
    }
    if (clone->uplink != self || IsService(clone)) {
        reply("OSMSG_NOT_A_CLONE", clone->nick);
        return 0;
    }
    if (!irccasecmp(argv[1], "REMOVE")) {
        const char *reason;
        if (argc > 3) {
            reason = unsplit_string(argv+3, argc-3, NULL);
        } else {
            char *tmp;
            tmp = alloca(strlen(clone->nick) + strlen(OSMSG_PART_REASON));
            sprintf(tmp, OSMSG_PART_REASON, clone->nick);
            reason = tmp;
        }
        DelUser(clone, NULL, 1, reason);
        reply("OSMSG_CLONE_REMOVED", argv[2]);
        return 1;
    }
    if (argc < 4) {
        reply("MSG_MISSING_PARAMS", argv[1]);
        OPSERV_SYNTAX();
        return 0;
    }
    channel = GetChannel(argv[3]);
    if (!irccasecmp(argv[1], "JOIN")) {
        if (!channel
            && !(channel = AddChannel(argv[3], now, NULL, NULL, NULL))) {
            reply("MSG_CHANNEL_UNKNOWN", argv[3]);
            return 0;
        }
        AddChannelUser(clone, channel);
        reply("OSMSG_CLONE_JOINED", clone->nick, channel->name);
        return 1;
    }
    if (!irccasecmp(argv[1], "PART")) {
        if (!channel) {
            reply("MSG_CHANNEL_UNKNOWN", argv[3]);
            return 0;
        }
        if (!GetUserMode(channel, clone)) {
            reply("OSMSG_NOT_ON_CHANNEL", clone->nick, channel->name);
            return 0;
        }
        reply("OSMSG_CLONE_PARTED", clone->nick, channel->name);
        DelChannelUser(clone, channel, "Leaving.", 0);
        return 1;
    }
    if (!irccasecmp(argv[1], "OP")) {
        struct mod_chanmode change;
        if (!channel) {
            reply("MSG_CHANNEL_UNKNOWN", argv[3]);
            return 0;
        }
        mod_chanmode_init(&change);
        change.argc = 1;
        change.args[0].mode = MODE_CHANOP;
        change.args[0].u.member = GetUserMode(channel, clone);
        if (!change.args[0].u.member) {
            reply("OSMSG_NOT_ON_CHANNEL", clone->nick, channel->name);
            return 0;
        }
        modcmd_chanmode_announce(&change);
        reply("OSMSG_OPS_GIVEN", channel->name, clone->nick);
        return 1;
    }
    if (!irccasecmp(argv[1], "HOP")) {
        struct mod_chanmode change;
        if (!channel) {
            reply("MSG_CHANNEL_UNKNOWN", argv[3]);
            return 0;
        }
        mod_chanmode_init(&change);
        change.argc = 1;
        change.args[0].mode = MODE_HALFOP;
        change.args[0].u.member = GetUserMode(channel, clone);
        if (!change.args[0].u.member) {
            reply("OSMSG_NOT_ON_CHANNEL", clone->nick, channel->name);
            return 0;
        }
        modcmd_chanmode_announce(&change);
        reply("OSMSG_HOPS_GIVEN", channel->name, clone->nick);
        return 1;
    }
    if (argc < 5) {
        reply("MSG_MISSING_PARAMS", argv[1]);
        OPSERV_SYNTAX();
        return 0;
    }
    if (!irccasecmp(argv[1], "SAY")) {
        char *text = unsplit_string(argv+4, argc-4, NULL);
        irc_privmsg(clone, argv[3], text);
        reply("OSMSG_CLONE_SAID", clone->nick, argv[3]);
        return 1;
    }
    reply("OSMSG_UNKNOWN_SUBCOMMAND", argv[1], argv[0]);
    return 0;
}

static struct helpfile_expansion
opserv_help_expand(const char *variable)
{
    extern struct userNode *message_source;
    struct helpfile_expansion exp;
    struct service *service;
    struct svccmd *cmd;
    dict_iterator_t it;
    int row;
    unsigned int level;

    if (!(service = service_find(message_source->nick))) {
        exp.type = HF_STRING;
        exp.value.str = NULL;
    } else if (!irccasecmp(variable, "index")) {
        exp.type = HF_TABLE;
        exp.value.table.length = 1;
        exp.value.table.width = 2;
        exp.value.table.flags = TABLE_REPEAT_HEADERS | TABLE_REPEAT_ROWS;
        exp.value.table.contents = calloc(dict_size(service->commands)+1, sizeof(char**));
        exp.value.table.contents[0] = calloc(exp.value.table.width, sizeof(char*));
        exp.value.table.contents[0][0] = "Command";
        exp.value.table.contents[0][1] = "Level";
        for (it=dict_first(service->commands); it; it=iter_next(it)) {
            cmd = iter_data(it);
            row = exp.value.table.length++;
            exp.value.table.contents[row] = calloc(exp.value.table.width, sizeof(char*));
            exp.value.table.contents[row][0] = iter_key(it);
            level = cmd->min_opserv_level;
            if (!level_strings[level]) {
                level_strings[level] = malloc(16);
                snprintf(level_strings[level], 16, "%3d", level);
            }
            exp.value.table.contents[row][1] = level_strings[level];
        }
    } else if (!strncasecmp(variable, "level", 5)) {
        cmd = dict_find(service->commands, variable+6, NULL);
        exp.type = HF_STRING;
        if (cmd) {
            level = cmd->min_opserv_level;
            exp.value.str = malloc(16);
            snprintf(exp.value.str, 16, "%3d", level);
        } else {
            exp.value.str = NULL;
        }
    } else {
        exp.type = HF_STRING;
        exp.value.str = NULL;
    }
    return exp;
}

struct modcmd *
opserv_define_func(const char *name, modcmd_func_t *func, int min_level, int reqchan, int min_argc)
{
    char buf[16], *flags = NULL;
    unsigned int iflags = 0;
    sprintf(buf, "%d", min_level);
    switch (reqchan) {
    case 1: flags = "+acceptchan"; break;
    case 3: flags = "+acceptpluschan"; /* fall through */
    case 2: iflags = MODCMD_REQUIRE_CHANNEL; break;
    }
    if (flags) {
        return modcmd_register(opserv_module, name, func, min_argc, iflags, "level", buf, "flags", flags, "flags", "+oper", NULL);
    } else {
        return modcmd_register(opserv_module, name, func, min_argc, iflags, "level", buf, "flags", "+oper", NULL);
    }
}

int add_reserved(const char *key, void *data, void *extra)
{
    struct chanNode *chan;
    struct record_data *rd = data;
    const char *ident, *hostname, *desc;
    unsigned int i;
    struct userNode *reserve;
    ident = database_get_data(rd->d.object, KEY_IDENT, RECDB_QSTRING);
    if (!ident) {
        log_module(OS_LOG, LOG_ERROR, "Missing ident for reserve of %s", key);
        return 0;
    }
    hostname = database_get_data(rd->d.object, KEY_HOSTNAME, RECDB_QSTRING);
    if (!hostname) {
        log_module(OS_LOG, LOG_ERROR, "Missing hostname for reserve of %s", key);
        return 0;
    }
    desc = database_get_data(rd->d.object, KEY_DESC, RECDB_QSTRING);
    if (!desc) {
        log_module(OS_LOG, LOG_ERROR, "Missing description for reserve of %s", key);
        return 0;
    }
    if ((reserve = AddClone(key, ident, hostname, desc))) {
        reserve->modes |= FLAGS_PERSISTENT;
        dict_insert(extra, reserve->nick, reserve);
    }

    if (autojoin_channels && reserve) {
        for (i = 0; i < autojoin_channels->used; i++) {
            chan = AddChannel(autojoin_channels->list[i], now, "+nt", NULL, NULL);
            AddChannelUser(reserve, chan)->modes |= MODE_VOICE;
        }
    }

    return 0;
}

static unsigned int
foreach_matching_user(const char *hostmask, discrim_search_func func, void *extra)
{
    discrim_t discrim;
    char *dupmask;
    unsigned int matched;

    if (!self->uplink) return 0;
    discrim = calloc(1, sizeof(*discrim));
    discrim->limit = dict_size(clients);
    discrim->max_level = ~0;
    discrim->max_ts = now;
    discrim->max_channels = INT_MAX;
    discrim->authed = -1;
    discrim->info_space = -1;
    discrim->intra_scmp = 0;
    discrim->intra_dcmp = 0;
    discrim->use_regex = 0;
    discrim->silent = 0;
    dupmask = strdup(hostmask);
    if (split_ircmask(dupmask, &discrim->mask_nick, &discrim->mask_ident, &discrim->mask_host)) {
        if (!irc_pton(&discrim->ip_mask, &discrim->ip_mask_bits, discrim->mask_host))
            discrim->ip_mask_bits = 0;
        matched = opserv_discrim_search(discrim, func, extra);
    } else {
        log_module(OS_LOG, LOG_ERROR, "Couldn't split IRC mask for gag %s!", hostmask);
        matched = 0;
    }
    free(discrim);
    free(dupmask);
    return matched;
}

static unsigned int
gag_free(struct gag_entry *gag)
{
    unsigned int ungagged;

    /* Remove from gag list */
    if (gagList == gag) {
        gagList = gag->next;
    } else {
        struct gag_entry *prev;
        for (prev = gagList; prev->next != gag; prev = prev->next) ;
        prev->next = gag->next;
    }

    ungagged = foreach_matching_user(gag->mask, ungag_helper_func, NULL);

    /* Deallocate storage */
    free(gag->reason);
    free(gag->owner);
    free(gag->mask);
    free(gag);

    return ungagged;
}

static void
gag_expire(void *data)
{
    gag_free(data);
}

unsigned int
gag_create(const char *mask, const char *owner, const char *reason, time_t expires)
{
    struct gag_entry *gag;

    /* Create gag and put it into linked list */
    gag = calloc(1, sizeof(*gag));
    gag->mask = strdup(mask);
    gag->owner = strdup(owner ? owner : "<unknown>");
    gag->reason = strdup(reason ? reason : "<unknown>");
    gag->expires = expires;
    if (gag->expires)
        timeq_add(gag->expires, gag_expire, gag);
    gag->next = gagList;
    gagList = gag;

    /* If we're linked, see if who the gag applies to */
    return foreach_matching_user(mask, gag_helper_func, gag);
}

static int
add_gag_helper(const char *key, void *data, UNUSED_ARG(void *extra))
{
    struct record_data *rd = data;
    char *owner, *reason, *expstr;
    time_t expires;

    owner = database_get_data(rd->d.object, KEY_OWNER, RECDB_QSTRING);
    reason = database_get_data(rd->d.object, KEY_REASON, RECDB_QSTRING);
    expstr = database_get_data(rd->d.object, KEY_EXPIRES, RECDB_QSTRING);
    expires = expstr ? strtoul(expstr, NULL, 0) : 0;
    gag_create(key, owner, reason, expires);

    return 0;
}

static struct opserv_user_alert *
opserv_add_user_alert(struct userNode *req, const char *name, opserv_alert_reaction reaction, const char *text_discrim, int last)
{
    unsigned int wordc;
    char *wordv[MAXNUMPARAMS], *discrim_copy;
    struct opserv_user_alert *alert;
    char *name_dup;

    if (dict_find(opserv_user_alerts, name, NULL)) {
        send_message(req, opserv, "OSMSG_ALERT_EXISTS", name);
        return NULL;
    }
    alert = malloc(sizeof(*alert));
    alert->owner = strdup(req->handle_info ? req->handle_info->handle : req->nick);
    alert->text_discrim = strdup(text_discrim);
    alert->last = last;
    discrim_copy = strdup(text_discrim); /* save a copy of the discrim */
    wordc = split_line(discrim_copy, false, ArrayLength(wordv), wordv);
    alert->discrim = opserv_discrim_create(req, opserv, wordc, wordv, 0);
    /* Check for missing required criteria or broken records */
    if (!alert->discrim || (reaction==REACT_SVSJOIN && !alert->discrim->chantarget) ||
       (reaction==REACT_SVSPART && !alert->discrim->chantarget) ||
       (reaction==REACT_MARK && !alert->discrim->mark)) {
        free(alert->text_discrim);
        free(discrim_copy);
        free(alert);
        return NULL;
    }
    alert->split_discrim = discrim_copy;
    name_dup = strdup(name);
    if (!alert->discrim->reason)
        alert->discrim->reason = strdup(name);
    alert->reaction = reaction;
    dict_insert(opserv_user_alerts, name_dup, alert);
    /* Stick the alert into the appropriate additional alert dict(s).
     * For channel alerts, we only use channels and min_channels;
     * max_channels would have to be checked on /part, which we do not
     * yet do, and which seems of questionable value.
     */
    if (alert->discrim->channel || alert->discrim->min_channels)
        dict_insert(opserv_channel_alerts, name_dup, alert);
    if (alert->discrim->mask_nick)
        dict_insert(opserv_nick_based_alerts, name_dup, alert);
    return alert;
}

/*
static int
add_chan_warn(const char *key, void *data, UNUSED_ARG(void *extra))
{
    struct record_data *rd = data;
    char *reason = GET_RECORD_QSTRING(rd);

    * i hope this can't happen *
    if (!reason)
        reason = "No Reason";

    dict_insert(opserv_chan_warn, strdup(key), strdup(reason));
    return 0;
}
*/


static int
add_user_alert(const char *key, void *data, UNUSED_ARG(void *extra))
{
    dict_t alert_dict;
    char *str;
    int last = 0;
    const char *discrim, *react, *owner;
    opserv_alert_reaction reaction;
    struct opserv_user_alert *alert;

    if (!(alert_dict = GET_RECORD_OBJECT((struct record_data *)data))) {
        log_module(OS_LOG, LOG_ERROR, "Bad type (not a record) for alert %s.", key);
        return 1;
    }
    discrim = database_get_data(alert_dict, KEY_DISCRIM, RECDB_QSTRING);
    react = database_get_data(alert_dict, KEY_REACTION, RECDB_QSTRING);
    str = database_get_data(alert_dict, KEY_LAST, RECDB_QSTRING);
    if (str)
      last = atoi(str);

    if (!react || !irccasecmp(react, "notice"))
        reaction = REACT_NOTICE;
    else if (!irccasecmp(react, "kill"))
        reaction = REACT_KILL;
    /*
    else if (!irccasecmp(react, "silent"))
        reaction = REACT_SILENT;
    */
    else if (!irccasecmp(react, "gline"))
        reaction = REACT_GLINE;
    else if (!irccasecmp(react, "track"))
        reaction = REACT_TRACK;
    else if (!irccasecmp(react, "shun"))
        reaction = REACT_SHUN;
    else if (!irccasecmp(react, "svsjoin"))
        reaction = REACT_SVSJOIN;
    else if (!irccasecmp(react, "svspart"))
        reaction = REACT_SVSPART;
    else if (!irccasecmp(react, "version"))
        reaction = REACT_VERSION;
    else if (!irccasecmp(react, "mark"))
        reaction = REACT_MARK;
    else {
        log_module(OS_LOG, LOG_ERROR, "Invalid reaction %s for alert %s.", react, key);
        return 0;
    }
    alert = opserv_add_user_alert(opserv, key, reaction, discrim, last);
    if (!alert) {
        log_module(OS_LOG, LOG_ERROR, "Unable to create alert %s from database.", key);
        return 0;
    }
    owner = database_get_data(alert_dict, KEY_OWNER, RECDB_QSTRING);
    free(alert->owner);
    alert->owner = strdup(owner ? owner : "<unknown>");
    return 0;
}

static int
trusted_host_read(const char *host, void *data, UNUSED_ARG(void *extra))
{
    struct record_data *rd = data;
    const char *limit, *str, *reason, *issuer;
    time_t issued, expires;

    if (rd->type == RECDB_QSTRING) {
        /* old style host by itself */
        limit = GET_RECORD_QSTRING(rd);
        issued = 0;
        issuer = NULL;
        expires = 0;
        reason = NULL;
    } else if (rd->type == RECDB_OBJECT) {
        dict_t obj = GET_RECORD_OBJECT(rd);
        /* new style structure */
        limit = database_get_data(obj, KEY_LIMIT, RECDB_QSTRING);
        str = database_get_data(obj, KEY_EXPIRES, RECDB_QSTRING);
        expires = str ? ParseInterval(str) : 0;
        reason = database_get_data(obj, KEY_REASON, RECDB_QSTRING);
        issuer = database_get_data(obj, KEY_ISSUER, RECDB_QSTRING);
        str = database_get_data(obj, KEY_ISSUED, RECDB_QSTRING);
        issued = str ? ParseInterval(str) : 0;
    } else
        return 0;

    if (expires && (expires < now))
        return 0;
    opserv_add_trusted_host(host, (limit ? strtoul(limit, NULL, 0) : 0), issuer, issued, expires, reason);
    return 0;
}

static int 
add_routing_plan_server(const char *name, void *data, void *rp)
{
    struct record_data *rd = data;
    const char *uplink, *portstr, *karma, *second, *offline;

    dict_t obj = GET_RECORD_OBJECT(rd);
    if(rd->type == RECDB_OBJECT) {
        uplink = database_get_data(obj, KEY_UPLINK, RECDB_QSTRING);
        second = database_get_data(obj, KEY_SECOND, RECDB_QSTRING);
        portstr = database_get_data(obj, KEY_PORT, RECDB_QSTRING);
        karma   = database_get_data(obj, KEY_KARMA, RECDB_QSTRING);
        offline = database_get_data(obj, KEY_OFFLINE, RECDB_QSTRING);
        /* create routing plan server named key, with uplink uplink. */
        opserv_routing_plan_add_server(rp, name, uplink, portstr ? atoi(portstr) : 0, 
                                       karma ? atoi(karma) : KARMA_DEFAULT, second, 
                                       offline ? atoi(offline) : 0);
    }
    return 0;

}

static int
routing_plan_set_option(const char *name, void *data, UNUSED_ARG(void *extra))
{
    struct record_data *rd = data;
    if(rd->type == RECDB_QSTRING)
    {
        char *value = GET_RECORD_QSTRING(rd);
        dict_insert(opserv_routing_plan_options, strdup(name), strdup(value));
    }
    return 0;
}

static int 
add_routing_plan(const char *name, void *data, UNUSED_ARG(void *extra))
{
    struct record_data *rd = data;
    struct routingPlan *rp;

    if(rd->type == RECDB_OBJECT) {
        dict_t obj = GET_RECORD_OBJECT(rd);
        rp = opserv_add_routing_plan(name);
        dict_foreach(obj, add_routing_plan_server, rp);
    }
    return 0;
}

static int
opserv_saxdb_read(struct dict *conf_db)
{
    dict_t object;
    struct record_data *rd;
    dict_iterator_t it;
    unsigned int nn;

    if ((object = database_get_data(conf_db, KEY_RESERVES, RECDB_OBJECT)))
        dict_foreach(object, add_reserved, opserv_reserved_nick_dict);
    if ((rd = database_get_path(conf_db, KEY_BAD_WORDS))) {
        switch (rd->type) {
        case RECDB_STRING_LIST:
            /* Add words one by one just in case there are overlaps from an old DB. */
            for (nn=0; nn<rd->d.slist->used; ++nn)
                opserv_add_bad_word(NULL, NULL, rd->d.slist->list[nn]);
            break;
        case RECDB_OBJECT:
            for (it=dict_first(rd->d.object); it; it=iter_next(it)) {
                opserv_add_bad_word(NULL, NULL, iter_key(it));
                rd = iter_data(it);
                if (rd->type == RECDB_STRING_LIST)
                    for (nn=0; nn<rd->d.slist->used; nn++)
                        dict_insert(opserv_exempt_channels, strdup(rd->d.slist->list[nn]), NULL);
            }
            break;
        default:
            /* do nothing */;
        }
    }
    if ((rd = database_get_path(conf_db, KEY_EXEMPT_CHANNELS))
        && (rd->type == RECDB_STRING_LIST)) {
        for (nn=0; nn<rd->d.slist->used; ++nn)
            dict_insert(opserv_exempt_channels, strdup(rd->d.slist->list[nn]), NULL);
    }
    if ((object = database_get_data(conf_db, KEY_MAX_CLIENTS, RECDB_OBJECT))) {
        char *str;
        if ((str = database_get_data(object, KEY_MAX, RECDB_QSTRING)))
            max_clients = atoi(str);
        if ((str = database_get_data(object, KEY_TIME, RECDB_QSTRING)))
            max_clients_time = atoi(str);
    }
    if ((object = database_get_data(conf_db, KEY_TRUSTED_HOSTS, RECDB_OBJECT)))
        dict_foreach(object, trusted_host_read, opserv_trusted_hosts);
    if ((object = database_get_data(conf_db, KEY_GAGS, RECDB_OBJECT)))
        dict_foreach(object, add_gag_helper, NULL);
    if ((object = database_get_data(conf_db, KEY_ALERTS, RECDB_OBJECT)))
        dict_foreach(object, add_user_alert, NULL);
/*
    if ((object = database_get_data(conf_db, KEY_WARN, RECDB_OBJECT)))
        dict_foreach(object, add_chan_warn, NULL);
*/

    if ((object = database_get_data(conf_db, KEY_ROUTINGPLAN, RECDB_OBJECT)))
        dict_foreach(object, add_routing_plan, NULL);

    if ((object = database_get_data(conf_db, KEY_ROUTINGPLAN_OPTIONS, RECDB_OBJECT)))
        dict_foreach(object, routing_plan_set_option, NULL);

    return 0;
}

static int
opserv_saxdb_write(struct saxdb_context *ctx)
{
    struct string_list *slist;
    dict_iterator_t it;

    /* reserved nicks */
    if (dict_size(opserv_reserved_nick_dict)) {
        saxdb_start_record(ctx, KEY_RESERVES, 1);
        for (it = dict_first(opserv_reserved_nick_dict); it; it = iter_next(it)) {
            struct userNode *user = iter_data(it);
            if (!IsPersistent(user)) continue;
            saxdb_start_record(ctx, iter_key(it), 0);
            saxdb_write_string(ctx, KEY_IDENT, user->ident);
            saxdb_write_string(ctx, KEY_HOSTNAME, user->hostname);
            saxdb_write_string(ctx, KEY_DESC, user->info);
            saxdb_end_record(ctx);
        }
        saxdb_end_record(ctx);
    }
    /* bad word set */
    if (opserv_bad_words->used) {
        saxdb_write_string_list(ctx, KEY_BAD_WORDS, opserv_bad_words);
    }
    /* routing plan options */
    if (dict_size(opserv_routing_plan_options)) {
        saxdb_start_record(ctx, KEY_ROUTINGPLAN_OPTIONS, 1);
        for(it = dict_first(opserv_routing_plan_options); it; it = iter_next(it)) {
            saxdb_write_string(ctx, iter_key(it), iter_data(it));
        }
        saxdb_end_record(ctx);
    }
    /* routing plans */
    if (dict_size(opserv_routing_plans)) {
        dict_iterator_t svrit;
        struct routingPlan *rp;
        struct routingPlanServer *rps;
        saxdb_start_record(ctx, KEY_ROUTINGPLAN, 1);
        for (it = dict_first(opserv_routing_plans); it; it = iter_next(it)) {
            rp = iter_data(it);
            saxdb_start_record(ctx, iter_key(it), 0);
            for(svrit = dict_first(rp->servers); svrit; svrit = iter_next(svrit)) {
                char buf[MAXLEN];
                rps = iter_data(svrit);
                saxdb_start_record(ctx, iter_key(svrit), 0);
                saxdb_write_string(ctx, KEY_UPLINK, rps->uplink);
                if(rps->secondaryuplink)
                    saxdb_write_string(ctx, KEY_SECOND, rps->secondaryuplink);
                sprintf(buf, "%d", rps->port);
                saxdb_write_string(ctx, KEY_PORT, buf);
                sprintf(buf, "%d", rps->karma);
                saxdb_write_string(ctx, KEY_KARMA, buf);
                sprintf(buf, "%d", rps->offline);
                saxdb_write_string(ctx, KEY_OFFLINE, buf);
                saxdb_end_record(ctx);
            }
            saxdb_end_record(ctx);
        }
        saxdb_end_record(ctx);
    }
    /* insert exempt channel names */
    if (dict_size(opserv_exempt_channels)) {
        slist = alloc_string_list(dict_size(opserv_exempt_channels));
        for (it=dict_first(opserv_exempt_channels); it; it=iter_next(it)) {
            string_list_append(slist, strdup(iter_key(it)));
        }
        saxdb_write_string_list(ctx, KEY_EXEMPT_CHANNELS, slist);
        free_string_list(slist);
    }
    /* trusted hosts takes a little more work */
    if (dict_size(opserv_trusted_hosts)) {
        saxdb_start_record(ctx, KEY_TRUSTED_HOSTS, 1);
        for (it = dict_first(opserv_trusted_hosts); it; it = iter_next(it)) {
            struct trusted_host *th = iter_data(it);
            saxdb_start_record(ctx, iter_key(it), 0);
            if (th->limit) saxdb_write_int(ctx, KEY_LIMIT, th->limit);
            if (th->expires) saxdb_write_int(ctx, KEY_EXPIRES, th->expires);
            if (th->issued) saxdb_write_int(ctx, KEY_ISSUED, th->issued);
            if (th->issuer) saxdb_write_string(ctx, KEY_ISSUER, th->issuer);
            if (th->reason) saxdb_write_string(ctx, KEY_REASON, th->reason);
            saxdb_end_record(ctx);
        }
        saxdb_end_record(ctx);
    }
    /* gags */
    if (gagList) {
        struct gag_entry *gag;
        saxdb_start_record(ctx, KEY_GAGS, 1);
        for (gag = gagList; gag; gag = gag->next) {
            saxdb_start_record(ctx, gag->mask, 0);
            saxdb_write_string(ctx, KEY_OWNER, gag->owner);
            saxdb_write_string(ctx, KEY_REASON, gag->reason);
            if (gag->expires) saxdb_write_int(ctx, KEY_EXPIRES, gag->expires);
            saxdb_end_record(ctx);
        }
        saxdb_end_record(ctx);
    }
    /* channel warnings */
    /*
    if (dict_size(opserv_chan_warn)) {
        saxdb_start_record(ctx, KEY_WARN, 0);
        for (it = dict_first(opserv_chan_warn); it; it = iter_next(it)) {
            saxdb_write_string(ctx, iter_key(it), iter_data(it));
        }
        saxdb_end_record(ctx);
    }
    */
    /* alerts */
    if (dict_size(opserv_user_alerts)) {
        saxdb_start_record(ctx, KEY_ALERTS, 1);
        for (it = dict_first(opserv_user_alerts); it; it = iter_next(it)) {
            struct opserv_user_alert *alert = iter_data(it);
            const char *reaction;
            saxdb_start_record(ctx, iter_key(it), 0);
            saxdb_write_string(ctx, KEY_DISCRIM, alert->text_discrim);
            saxdb_write_string(ctx, KEY_OWNER, alert->owner);
            saxdb_write_int(ctx, KEY_LAST, alert->last);
            switch (alert->reaction) {
            case REACT_NOTICE: reaction = "notice"; break;
            case REACT_KILL: reaction = "kill"; break;
//            case REACT_SILENT: reaction = "silent"; break;
            case REACT_GLINE: reaction = "gline"; break;
            case REACT_TRACK: reaction = "track"; break;
            case REACT_SHUN: reaction = "shun"; break;
            case REACT_SVSJOIN: reaction = "svsjoin"; break;
            case REACT_SVSPART: reaction = "svspart"; break;
            case REACT_VERSION: reaction = "version"; break;
            case REACT_MARK: reaction = "mark"; break;
            default:
                reaction = NULL;
                log_module(OS_LOG, LOG_ERROR, "Invalid reaction type %d for alert %s (while writing database).", alert->reaction, iter_key(it));
                break;
            }
            if (reaction) saxdb_write_string(ctx, KEY_REACTION, reaction);
            saxdb_end_record(ctx);
        }
        saxdb_end_record(ctx);
    }
    /* max clients */
    saxdb_start_record(ctx, KEY_MAX_CLIENTS, 0);
    saxdb_write_int(ctx, KEY_MAX, max_clients);
    saxdb_write_int(ctx, KEY_TIME, max_clients_time);
    saxdb_end_record(ctx);
    return 0;
}

static int
query_keys_helper(const char *key, UNUSED_ARG(void *data), void *extra)
{
    send_message_type(4, extra, opserv, "$b%s$b", key);
    return 0;
}

static MODCMD_FUNC(cmd_query)
{
    struct record_data *rd;
    unsigned int i;
    char *nodename;

    if (argc < 2) {
        reply("OSMSG_OPTION_ROOT");
        conf_enum_root(query_keys_helper, user);
        return 1;
    }

    nodename = unsplit_string(argv+1, argc-1, NULL);
    if (!(rd = conf_get_node(nodename))) {
        reply("OSMSG_UNKNOWN_OPTION", nodename);
        return 0;
    }

    if (rd->type == RECDB_QSTRING)
        reply("OSMSG_OPTION_IS", nodename, rd->d.qstring);
    else if (rd->type == RECDB_STRING_LIST) {
        reply("OSMSG_OPTION_LIST", nodename);
        if (rd->d.slist->used)
            for (i=0; i<rd->d.slist->used; i++)
                send_message_type(4, user, cmd->parent->bot, "$b%s$b", rd->d.slist->list[i]);
        else
            reply("OSMSG_OPTION_LIST_EMPTY");
    } else if (rd->type == RECDB_OBJECT) {
        reply("OSMSG_OPTION_KEYS", nodename);
        dict_foreach(rd->d.object, query_keys_helper, user);
    }

    return 1;
}

static MODCMD_FUNC(cmd_set)
{
    struct record_data *rd;

    /* I originally wanted to be able to fully manipulate the config
       db with this, but i wussed out. feel free to fix this - you'll
       need to handle quoted strings which have been split, and likely
       invent a syntax for it. -Zoot */

    if (!(rd = conf_get_node(argv[1]))) {
        reply("OSMSG_SET_NOT_SET", argv[1]);
        return 0;
    }

    if (rd->type != RECDB_QSTRING) {
        reply("OSMSG_SET_BAD_TYPE", argv[1]);
        return 0;
    }

    free(rd->d.qstring);
    rd->d.qstring = strdup(argv[2]);
    conf_call_reload_funcs();
    reply("OSMSG_SET_SUCCESS", argv[1], argv[2]);
    return 1;
}

static MODCMD_FUNC(cmd_settime)
{
    const char *srv_name_mask = "*";
    time_t new_time = now;

    if (argc > 1)
        srv_name_mask = argv[1];
    if (argc > 2)
        new_time = time(NULL);
    irc_settime(srv_name_mask, new_time);
    reply("OSMSG_SETTIME_SUCCESS", srv_name_mask);
    return 1;
}

static discrim_t
opserv_discrim_create(struct userNode *user, struct userNode *bot, unsigned int argc, char *argv[], int allow_channel)
{
    unsigned int i, j;
    discrim_t discrim;

    discrim = calloc(1, sizeof(*discrim));
    discrim->limit = 250;
    discrim->max_level = ~0;
    discrim->max_ts = INT_MAX;
    discrim->domain_depth = 2;
    discrim->max_channels = INT_MAX;
    discrim->authed = -1;
    discrim->info_space = -1;
    discrim->intra_dcmp = 0;
    discrim->intra_scmp = 0;
    discrim->use_regex = 0;
    discrim->silent = 0;

    for (i=0; i<argc; i++) {
        if (irccasecmp(argv[i], "log") == 0) {
            discrim->option_log = 1;
            continue;
        }
        /* Assume all other criteria require arguments. */
        if (i == argc - 1) {
            send_message(user, bot, "MSG_MISSING_PARAMS", argv[i]);
            goto fail;
        }
        if (argv[i+1][0] == '&') {
            /* Looking for intra-userNode matches */
            char *tmp = &(argv[i+1][1]);
            if (strcasecmp(tmp, argv[i]) != 0) { /* Don't allow "nick &nick" etc */
                if (!strcasecmp(tmp, "nick"))
                    discrim->intra_dcmp = 1;
                else if (!strcasecmp(tmp, "ident"))
                    discrim->intra_dcmp = 2;
                else if (!strcasecmp(tmp, "info"))
                    discrim->intra_dcmp = 3;
            }
        }
        if (irccasecmp(argv[i], "mask") == 0) {
            if (!is_ircmask(argv[++i])) {
                send_message(user, bot, "OSMSG_INVALID_IRCMASK", argv[i]);
                goto fail;
            }
            if (!split_ircmask(argv[i],
                               &discrim->mask_nick,
                               &discrim->mask_ident,
                               &discrim->mask_host)) {
                send_message(user, bot, "OSMSG_INVALID_IRCMASK", argv[i]);
                goto fail;
            }
        } else if (irccasecmp(argv[i], "nick") == 0) {
            i++;
            if (discrim->intra_dcmp > 0)
                discrim->intra_scmp = 1;
	    else
                discrim->mask_nick = argv[i];
        } else if (irccasecmp(argv[i], "ident") == 0) {
            i++;
            if (discrim->intra_dcmp > 0)
                discrim->intra_scmp = 2;
	    else
                discrim->mask_ident = argv[i];
        } else if (irccasecmp(argv[i], "host") == 0) {
            discrim->mask_host = argv[++i];
        } else if (irccasecmp(argv[i], "info") == 0) {
            i++;
            if (discrim->intra_dcmp > 0)
                discrim->intra_scmp = 3;
	    else
                discrim->mask_info = argv[i];
        } else if (irccasecmp(argv[i], "version") == 0) {
            discrim->mask_version = argv[++i];
        } else if (irccasecmp(argv[i], "server") == 0) {
            discrim->server = argv[++i];
        } else if (irccasecmp(argv[i], "ip") == 0) {
            j = irc_pton(&discrim->ip_mask, &discrim->ip_mask_bits, argv[++i]);
            if (!j) {
                send_message(user, bot, "OSMSG_BAD_IP", argv[i]);
                goto fail;
            }
    } else if (irccasecmp(argv[i], "account") == 0) {
        if (discrim->authed == 0) {
            send_message(user, bot, "OSMSG_ACCOUNTMASK_AUTHED");
            goto fail;
        }
        discrim->accountmask = argv[++i];
        discrim->authed = 1;
    } else if (irccasecmp(argv[i], "marked") == 0) {
        discrim->mask_mark = argv[++i];
    } else if (irccasecmp(argv[i], "chantarget") == 0) {
            if(!IsChannelName(argv[i+1])) {
                send_message(user, bot, "MSG_NOT_CHANNEL_NAME");
                goto fail;
            }
            discrim->chantarget = argv[++i];
    } else if (irccasecmp(argv[i], "checkrestrictions") == 0) {
        i++;
        if (true_string(argv[i])) {
            discrim->checkrestrictions = 1;
        } else if (false_string(argv[i])) {
            discrim->checkrestrictions = 0;
        } else {
            send_message(user, bot, "MSG_INVALID_BINARY", argv[i]);
            goto fail;
        }
    } else if (irccasecmp(argv[i], "mark") == 0) {
        if(!is_valid_mark(argv[i+1])) {
            send_message(user, bot, "OSMSG_MARK_INVALID");
            goto fail;
        }
        discrim->mark = argv[++i];
    } else if (irccasecmp(argv[i], "authed") == 0) {
        i++; /* true_string and false_string are macros! */
        if (true_string(argv[i])) {
            discrim->authed = 1;
        } else if (false_string(argv[i])) {
            if (discrim->accountmask) {
                send_message(user, bot, "OSMSG_ACCOUNTMASK_AUTHED");
                goto fail;
            }
            discrim->authed = 0;
        } else {
            send_message(user, bot, "MSG_INVALID_BINARY", argv[i]);
            goto fail;
        }
    } else if (irccasecmp(argv[i], "info_space") == 0) {
        /* XXX: A hack because you can't check explicitly for a space through
         * any other means */
        i++;
        if (true_string(argv[i])) {
            discrim->info_space = 1;
        } else if (false_string(argv[i])) {
            discrim->info_space = 0;
        } else {
            send_message(user, bot, "MSG_INVALID_BINARY", argv[i]);
            goto fail;
        }
    } else if (irccasecmp(argv[i], "regex") == 0) {
        i++;
        if (true_string(argv[i])) {
            discrim->use_regex = 1;
        } else if (false_string(argv[i])) {
            discrim->use_regex = 0;
        } else {
            send_message(user, bot, "MSG_INVALID_BINARY", argv[i]);
            goto fail;
        }
    } else if (irccasecmp(argv[i], "silent") == 0) {
        i++;
        if(user != opserv && !oper_has_access(user, opserv, opserv_conf.silent_level, 0)) {
            goto fail;
        } else if (true_string(argv[i])) {
            discrim->silent = 1;
        } else if (false_string(argv[i])) {
            discrim->silent = 0;
        } else {
            send_message(user, bot, "MSG_INVALID_BINARY", argv[i]);
            goto fail;
        }
    } else if (irccasecmp(argv[i], "duration") == 0) {
        discrim->duration = ParseInterval(argv[++i]);
        } else if (irccasecmp(argv[i], "channel") == 0) {
            for (j=0, i++; ; j++) {
                switch (argv[i][j]) {
                case '#':
                    goto find_channel;
                case '-':
                    discrim->chan_no_modes  |= MODE_CHANOP | MODE_HALFOP | MODE_VOICE;
                    break;
                case '+':
                    discrim->chan_req_modes |= MODE_VOICE;
                    discrim->chan_no_modes  |= MODE_CHANOP;
                    discrim->chan_no_modes  |= MODE_HALFOP;
                    break;
                case '%':
                    discrim->chan_req_modes |= MODE_HALFOP;
                    discrim->chan_no_modes  |= MODE_CHANOP;
                    discrim->chan_no_modes  |= MODE_VOICE;
                    break;
                case '@':
                    discrim->chan_req_modes |= MODE_CHANOP;
                    break;
                case '\0':
                    send_message(user, bot, "MSG_NOT_CHANNEL_NAME");
                    goto fail;
                }
            }
          find_channel:
            discrim->chan_no_modes &= ~discrim->chan_req_modes;
            if (!(discrim->channel = GetChannel(argv[i]+j))) {
                /* secretly "allow_channel" now means "if a channel name is
                 * specified, require that it currently exist" */
                if (allow_channel) {
                    send_message(user, bot, "MSG_CHANNEL_UNKNOWN", argv[i]);
                    goto fail;
                } else {
                    discrim->channel = AddChannel(argv[i]+j, now, NULL, NULL, NULL);
                }
            }
            LockChannel(discrim->channel);
        } else if (irccasecmp(argv[i], "numchannels") == 0) {
            discrim->min_channels = discrim->max_channels = strtoul(argv[++i], NULL, 10);
        } else if (irccasecmp(argv[i], "limit") == 0) {
            discrim->limit = strtoul(argv[++i], NULL, 10);
        } else if (irccasecmp(argv[i], "reason") == 0) {
            discrim->reason = strdup(unsplit_string(argv+i+1, argc-i-1, NULL));
            i = argc;
        } else if (irccasecmp(argv[i], "last") == 0) {
            discrim->min_ts = now - ParseInterval(argv[++i]);
        } else if ((irccasecmp(argv[i], "linked") == 0)
                   || (irccasecmp(argv[i], "nickage") == 0)) {
            const char *cmp = argv[++i];
            if (cmp[0] == '<') {
                if (cmp[1] == '=') {
                    discrim->min_ts = now - ParseInterval(cmp+2);
                } else {
                    discrim->min_ts = now - (ParseInterval(cmp+1) - 1);
                }
            } else if (cmp[0] == '>') {
                if (cmp[1] == '=') {
                    discrim->max_ts = now - ParseInterval(cmp+2);
                } else {
                    discrim->max_ts = now - (ParseInterval(cmp+1) - 1);
                }
            } else {
                discrim->min_ts = now - ParseInterval(cmp+2);
            }
        } else if (irccasecmp(argv[i], "access") == 0) {
            const char *cmp = argv[++i];
            if (cmp[0] == '<') {
                if (discrim->min_level == 0) discrim->min_level = 1;
                if (cmp[1] == '=') {
                    discrim->max_level = strtoul(cmp+2, NULL, 0);
                } else {
                    discrim->max_level = strtoul(cmp+1, NULL, 0) - 1;
                }
            } else if (cmp[0] == '=') {
                discrim->min_level = discrim->max_level = strtoul(cmp+1, NULL, 0);
            } else if (cmp[0] == '>') {
                if (cmp[1] == '=') {
                    discrim->min_level = strtoul(cmp+2, NULL, 0);
                } else {
                    discrim->min_level = strtoul(cmp+1, NULL, 0) + 1;
                }
            } else {
                discrim->min_level = strtoul(cmp+2, NULL, 0);
            }
        } else if ((irccasecmp(argv[i], "abuse") == 0)
                   && (irccasecmp(argv[++i], "opers") == 0)) {
            discrim->match_opers = 1;
        } else if (irccasecmp(argv[i], "depth") == 0) {
            discrim->domain_depth = strtoul(argv[++i], NULL, 0);
        } else if (irccasecmp(argv[i], "clones") == 0) {
            discrim->min_clones = strtoul(argv[++i], NULL, 0);
	} else if (irccasecmp(argv[i], "modes") == 0) {
  	    discrim->modes = argv[++i];
        } else {
            send_message(user, bot, "MSG_INVALID_CRITERIA", argv[i]);
            goto fail;
        }
    }

    if (discrim->mask_nick && !strcmp(discrim->mask_nick, "*")) {
        discrim->mask_nick = 0;
    }
    if (discrim->mask_ident && !strcmp(discrim->mask_ident, "*")) {
        discrim->mask_ident = 0;
    }
    if (discrim->mask_info && !strcmp(discrim->mask_info, "*")) {
        discrim->mask_info = 0;
    }
    if (discrim->mask_version && !strcmp(discrim->mask_version, "*")) {
        discrim->mask_version = 0;
    }
    if (discrim->mask_host && !discrim->mask_host[strspn(discrim->mask_host, "*.")]) {
        discrim->mask_host = 0;
    }

    if(discrim->use_regex)
    {
        if(discrim->mask_nick)
        {
            int err = regcomp(&discrim->regex_nick, discrim->mask_nick, REG_EXTENDED|REG_NOSUB);
            discrim->has_regex_nick = !err;
            if(err)
            {
                char buff[256];
                buff[regerror(err, &discrim->regex_nick, buff, sizeof(buff))] = 0;

                send_message(user, bot, "OSMSG_INVALID_REGEX", discrim->mask_nick, buff, err);
                goto regfail;
            }
        }

        if(discrim->mask_ident)
        {
            int err = regcomp(&discrim->regex_ident, discrim->mask_ident, REG_EXTENDED|REG_NOSUB);
            discrim->has_regex_ident = !err;
            if(err)
            {
                char buff[256];
                buff[regerror(err, &discrim->regex_ident, buff, sizeof(buff))] = 0;

                send_message(user, bot, "OSMSG_INVALID_REGEX", discrim->mask_ident, buff, err);
                goto regfail;
            }
        }

        if(discrim->mask_host)
        {
            int err = regcomp(&discrim->regex_host, discrim->mask_host, REG_EXTENDED|REG_NOSUB);
            discrim->has_regex_host = !err;
            if(err)
            {
                char buff[256];
                buff[regerror(err, &discrim->regex_host, buff, sizeof(buff))] = 0;

                send_message(user, bot, "OSMSG_INVALID_REGEX", discrim->mask_host, buff, err);
                goto regfail;
            }
        }

        if(discrim->mask_info)
        {
            int err = regcomp(&discrim->regex_info, discrim->mask_info, REG_EXTENDED|REG_NOSUB);
            discrim->has_regex_info = !err;
            if(err)
            {
                char buff[256];
                buff[regerror(err, &discrim->regex_info, buff, sizeof(buff))] = 0;

                send_message(user, bot, "OSMSG_INVALID_REGEX", discrim->mask_info, buff, err);
                goto regfail;
            }
        }

        if(discrim->mask_version)
        {
            int err = regcomp(&discrim->regex_version, discrim->mask_version, REG_EXTENDED|REG_NOSUB);
            discrim->has_regex_version = !err;
            if(err)
            {
                char buff[256];
                buff[regerror(err, &discrim->regex_version, buff, sizeof(buff))] = 0;

                send_message(user, bot, "OSMSG_INVALID_REGEX", discrim->mask_version, buff, err);
                goto regfail;
            }
        }
    }

    return discrim;

  fail:
    free(discrim);
    return NULL;

  regfail:
    if(discrim->has_regex_nick)
      regfree(&discrim->regex_nick);
    if(discrim->has_regex_ident)
      regfree(&discrim->regex_ident);
    if(discrim->has_regex_host)
      regfree(&discrim->regex_host);
    if(discrim->has_regex_info)
      regfree(&discrim->regex_info);

    free(discrim);
    return NULL;
}

static int
discrim_match(discrim_t discrim, struct userNode *user)
{
    unsigned int access;
    char *scmp=NULL, *dcmp=NULL;

    if ((user->timestamp < discrim->min_ts)
        || (user->timestamp > discrim->max_ts)
        || (user->channels.used < discrim->min_channels)
        || (user->channels.used > discrim->max_channels)
        || (discrim->authed == 0 && user->handle_info)
        || (discrim->authed == 1 && !user->handle_info)
        || (discrim->info_space == 0 && user->info[0] == ' ')
        || (discrim->info_space == 1 && user->info[0] != ' ')
        || (discrim->server && !match_ircglob(user->uplink->name, discrim->server))
        || (discrim->mask_mark && (!user->mark || !match_ircglob(user->mark, discrim->mask_mark)))
        || (discrim->accountmask && (!user->handle_info || !match_ircglob(user->handle_info->handle, discrim->accountmask)))
        || (discrim->ip_mask_bits && !irc_check_mask(&user->ip, &discrim->ip_mask, discrim->ip_mask_bits))
        )
        return 0;

    if (discrim->channel && !GetUserMode(discrim->channel, user))
        return 0;

    if(discrim->use_regex)
    {
        if((discrim->has_regex_nick && regexec(&discrim->regex_nick, user->nick, 0, 0, 0))
           || (discrim->has_regex_ident && regexec(&discrim->regex_ident, user->ident, 0, 0, 0))
           || (discrim->has_regex_host && regexec(&discrim->regex_host, user->hostname, 0, 0, 0))
           || (discrim->has_regex_info && regexec(&discrim->regex_info, user->info, 0, 0, 0))
           || (discrim->has_regex_version && (!user->version_reply || regexec(&discrim->regex_version, user->version_reply, 0, 0, 0)))) {
           return 0;
           }
    }
    else
    {
        if ((discrim->mask_nick && !match_ircglob(user->nick, discrim->mask_nick))
            || (discrim->mask_ident && !match_ircglob(user->ident, discrim->mask_ident))
            || (discrim->mask_host && !match_ircglob(user->hostname, discrim->mask_host))
            || (discrim->mask_info && !match_ircglob(user->info, discrim->mask_info))
            || (discrim->mask_version && (!user->version_reply || !match_ircglob(user->version_reply, discrim->mask_version))) ) {
            return 0;
        }
    }

    if ((discrim->intra_scmp > 0 && discrim->intra_dcmp > 0)) {
       switch(discrim->intra_scmp) {
            case 1: scmp=user->nick; break;
            case 2: scmp=user->ident; break;
            case 3: 
                scmp=user->info; 
                if (discrim->info_space == 1) scmp++;
                break;
        }
        switch(discrim->intra_dcmp) {
            case 1: dcmp=user->nick; break;
            case 2: dcmp=user->ident; break;
            case 3: /* When checking INFO, and info_space is enabled
                     * ignore the first character in a search 
                     * XXX: Should we ignore ALL leading whitespace?
                     *      Also, what about ignoring ~ in ident?
                     */
                dcmp=user->info; 
                if (discrim->info_space == 1) dcmp++;
                break;
        }
        if (irccasecmp(scmp,dcmp))
            return 0;
    }

    if (discrim->modes) {
	    unsigned int ii, matches = 0;
        for (ii = 0; ii < strlen(discrim->modes); ii++) {
            switch(discrim->modes[ii]) {
                case 'O':
                    if(IsOper(user)) matches++;
                    break;
                case 'o':
                    if(IsOper(user)) matches++;
                    break;
                case 'i':
                    if(IsInvisible(user)) matches++;
                    break;
                case 'w':
                    if(IsWallOp(user)) matches++;
                    break;
                case 's':
                    if(IsServNotice(user)) matches++;
                    break;
                case 'd':
                    if(IsDeaf(user)) matches++;
                    break;
                case 'k':
                    if(IsService(user)) matches++;
                    break;
                case 'g':
                    if(IsGlobal(user)) matches++;
                    break;
                case 'h':
                    if(IsSetHost(user)) matches++;
                    break;
                case 'B':
                    if(IsBotM(user)) matches++;
                    break;
                case 'n':
                    if(IsHideChans(user)) matches++;
                    break;
                case 'I':
                    if(IsHideIdle(user)) matches++;
                    break;
                case 'X':
                    if(IsXtraOp(user)) matches++;
                    break;
                case 'x':
                    if(IsHiddenHost(user)) matches++;
                    break;
            }
        }
        if (matches != strlen(discrim->modes)) return 0;
    }

    access = user->handle_info ? user->handle_info->opserv_level : 0;
    if ((access < discrim->min_level)
        || (access > discrim->max_level)) {
        return 0;
    }
    if (discrim->min_clones > 1) {
        struct opserv_hostinfo *ohi = dict_find(opserv_hostinfo_dict, irc_ntoa(&user->ip), NULL);
        if (!ohi || (ohi->clients.used < discrim->min_clones))
            return 0;
    }
    return 1;
}

static unsigned int
opserv_discrim_search(discrim_t discrim, discrim_search_func dsf, void *data)
{
    unsigned int nn, count;
    struct userList matched;

    userList_init(&matched);
    /* Try most optimized search methods first */
    if (discrim->channel) {
        for (nn=0;
                (nn < discrim->channel->members.used)
                && (matched.used < discrim->limit);
                nn++) {
            struct modeNode *mn = discrim->channel->members.list[nn];
            if (((mn->modes & discrim->chan_req_modes) != discrim->chan_req_modes)
                    || ((mn->modes & discrim->chan_no_modes) != 0)) {
                continue;
            }
            if (discrim_match(discrim, mn->user)) {
                userList_append(&matched, mn->user);
            }
        }
    } else if (discrim->ip_mask_bits == 128) {
        struct opserv_hostinfo *ohi = dict_find(opserv_hostinfo_dict, irc_ntoa(&discrim->ip_mask), NULL);
        if (!ohi) {
            userList_clean(&matched);
            return 0;
        }
        for (nn=0; (nn<ohi->clients.used) && (matched.used < discrim->limit); nn++) {
            if (discrim_match(discrim, ohi->clients.list[nn])) {
                userList_append(&matched, ohi->clients.list[nn]);
            }
        }
    } else {
        dict_iterator_t it;
        for (it=dict_first(clients); it && (matched.used < discrim->limit); it=iter_next(it)) {
            if (discrim_match(discrim, iter_data(it))) {
                userList_append(&matched, iter_data(it));
            }
        }
    }

    if (!matched.used) {
        userList_clean(&matched);
        return 0;
    }

    if (discrim->option_log) {
        log_module(OS_LOG, LOG_INFO, "Logging matches for search:");
    }
    for (nn=0; nn<matched.used; nn++) {
        struct userNode *user = matched.list[nn];
        if (discrim->option_log) {
            log_module(OS_LOG, LOG_INFO, "  %s!%s@%s", user->nick, user->ident, user->hostname);
        }
        if (dsf(user, data)) {
            /* If a search function returns true, it ran into a
               problem. Stop going through the list. */
            break;
        }
    }
    if (discrim->option_log) {
        log_module(OS_LOG, LOG_INFO, "End of matching users.");
    }
    count = matched.used;
    userList_clean(&matched);
    return count;
}

static int
trace_print_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;
    if (match->handle_info) {
        send_message_type(4, das->source, das->destination, "%-15s\002 \002%10s\002@\002%s (%s)", match->nick, match->ident, match->hostname, match->handle_info->handle);
    } else {
        send_message_type(4, das->source, das->destination, "%-15s\002 \002%10s\002@\002%s", match->nick, match->ident, match->hostname);
    }
    return 0;
}

static int
trace_count_func(UNUSED_ARG(struct userNode *match), UNUSED_ARG(void *extra))
{
    return 0;
}

static int
is_oper_victim(struct userNode *user, struct userNode *target, int match_opers)
{
    return !(IsService(target)
             || (!match_opers && IsOper(target))
             || (target->handle_info
                 && target->handle_info->opserv_level > user->handle_info->opserv_level));
}

static int
trace_gline_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;

    if (is_oper_victim(das->source, match, das->discrim->match_opers)) {
        opserv_block(match, das->source->handle_info->handle, das->discrim->reason, das->discrim->duration, das->discrim->silent);
    }

    return 0;
}

static int
trace_shun_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;

    if (is_oper_victim(das->source, match, das->discrim->match_opers)) {
        opserv_shun(match, das->source->handle_info->handle, das->discrim->reason, das->discrim->duration);
    }

    return 0;
}

static int
trace_kill_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;

    if (is_oper_victim(das->source, match, das->discrim->match_opers)) {
        char *reason;
        if (das->discrim->reason) {
            reason = das->discrim->reason;
        } else {
            reason = alloca(strlen(OSMSG_KILL_REQUESTED)+strlen(das->source->nick)+1);
            sprintf(reason, OSMSG_KILL_REQUESTED, das->source->nick);
        }
        DelUser(match, opserv, 1, reason);
    }

    return 0;
}

static int
trace_mark_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;
    char *mark = das->discrim->mark;

    if(!mark)
       return 1;
    irc_mark(match, mark);
    return 0;
}

static int
trace_svsjoin_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;

    char *channame = das->discrim->chantarget;
    int checkrestrictions = das->discrim->checkrestrictions;
    struct chanNode *channel;

    if(!channame || !IsChannelName(channame)) {
        //reply("MSG_NOT_CHANNEL_NAME");
        return 1;
    }

    if (!(channel = GetChannel(channame))) {
       channel = AddChannel(channame, now, NULL, NULL, NULL);
    }

    if (checkrestrictions) {
        if (trace_check_bans(match, channel) == 1) {
            return 1; /* found on lamer list */
        }

        if (channel->modes & MODE_INVITEONLY) {
            return 1; /* channel is invite only */
        }

        if (channel->limit > 0) {
            if (channel->members.used >= channel->limit) {
                return 1; /* channel is invite on */
            }
        }

        if (*channel->key) {
            return 1; /* channel is password protected */
        }
    }

    if (GetUserMode(channel, match)) {
//        reply("OSMSG_ALREADY_THERE", channel->name);
        return 1;
    }
    irc_svsjoin(opserv, match, channel);
 //   reply("OSMSG_SVSJOIN_SENT");
    return 0;
}

static int
trace_svspart_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;
    char *channame = das->discrim->chantarget;
    struct chanNode *channel;

    if(!channame || !IsChannelName(channame))
       return 1;

    if (!(channel = GetChannel(channame)))
       return 1;

    if (!GetUserMode(channel, match))
        return 1;

    irc_svspart(opserv, match, channel);
    return 0;
}

static int
trace_version_func(struct userNode *match, UNUSED_ARG(void *extra))
{
    irc_version_user(opserv, match);
    return 0;
}

static int
is_gagged(char *mask)
{
    struct gag_entry *gag;

    for (gag = gagList; gag; gag = gag->next) {
        if (match_ircglobs(gag->mask, mask)) return 1;
    }
    return 0;
}

static int
trace_gag_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;

    if (is_oper_victim(das->source, match, das->discrim->match_opers)) {
        char *reason, *mask;
        int masksize;
        if (das->discrim->reason) {
            reason = das->discrim->reason;
        } else {
            reason = alloca(strlen(OSMSG_GAG_REQUESTED)+strlen(das->source->nick)+1);
            sprintf(reason, OSMSG_GAG_REQUESTED, das->source->nick);
        }
        masksize = 5+strlen(match->hostname);
        mask = alloca(masksize);
        snprintf(mask, masksize, "*!*@%s", match->hostname);
        if (!is_gagged(mask)) {
            gag_create(mask, das->source->handle_info->handle, reason,
                       das->discrim->duration ? (now + das->discrim->duration) : 0);
        }
    }

    return 0;
}

static int
trace_domains_func(struct userNode *match, void *extra)
{
    struct discrim_and_source *das = extra;
    irc_in_addr_t ip;
    unsigned long *count;
    unsigned int depth;
    char *hostname;
    char ipmask[IRC_NTOP_MASK_MAX_SIZE];

    if (irc_pton(&ip, NULL, match->hostname)) {
        if (irc_in_addr_is_ipv4(ip)) {
            unsigned long matchip = ntohl(ip.in6_32[3]);
            /* raw IP address.. use up to first three octets of IP */
            switch (das->discrim->domain_depth) {
            default:
                snprintf(ipmask, sizeof(ipmask), "%lu.%lu.%lu.*", (matchip>>24)&255, (matchip>>16)&255, (matchip>>8)&255);
                break;
            case 2:
                snprintf(ipmask, sizeof(ipmask), "%lu.%lu.*", (matchip>>24)&255, (matchip>>16)&255);
                break;
            case 1:
                snprintf(ipmask, sizeof(ipmask), "%lu.*", (matchip>>24)&255);
                break;
            }
        } else if (irc_in_addr_is_ipv6(ip)) {
            switch (das->discrim->domain_depth) {
            case 1:  depth = 16; goto ipv6_pfx;
            case 2:  depth = 24; goto ipv6_pfx;
            case 3:  depth = 32; goto ipv6_pfx;
            default: depth = das->discrim->domain_depth;
            ipv6_pfx:
                irc_ntop_mask(ipmask, sizeof(ipmask), &ip, depth);
            }
        } else safestrncpy(ipmask, match->hostname, sizeof(ipmask));
        ipmask[sizeof(ipmask) - 1] = '\0';
        hostname = ipmask;
    } else {
        hostname = match->hostname + strlen(match->hostname);
        for (depth=das->discrim->domain_depth;
             depth && (hostname > match->hostname);
             depth--) {
            hostname--;
            while ((hostname > match->hostname) && (*hostname != '.')) hostname--;
        }
        if (*hostname == '.') hostname++; /* advance past last dot we saw */
    }
    if (!(count = dict_find(das->dict, hostname, NULL))) {
        count = calloc(1, sizeof(*count));
        dict_insert(das->dict, strdup(hostname), count);
    }
    (*count)++;
    return 0;
}

static int
opserv_show_hostinfo(const char *key, void *data, void *extra)
{
    unsigned long *count = data;
    struct discrim_and_source *das = extra;

    send_message_type(4, das->source, das->destination, "%s %lu", key, *count);
    return !--das->disp_limit;
}

static MODCMD_FUNC(cmd_trace)
{
    struct discrim_and_source das;
    discrim_search_func action;
    unsigned int matches;
    struct svccmd *subcmd;
    char buf[MAXLEN];
    int ret = 1;

    sprintf(buf, "trace %s", argv[1]);
    if (!(subcmd = dict_find(opserv_service->commands, buf, NULL))) {
        reply("OSMSG_BAD_ACTION", argv[1]);
        return 0;
    }
    if (!svccmd_can_invoke(user, opserv_service->bot, subcmd, channel, SVCCMD_NOISY))
        return 0;
    if (!irccasecmp(argv[1], "print"))
        action = trace_print_func;
    else if (!irccasecmp(argv[1], "count"))
        action = trace_count_func;
    else if (!irccasecmp(argv[1], "domains"))
        action = trace_domains_func;
    else if (!irccasecmp(argv[1], "gline"))
        action = trace_gline_func;
    else if (!irccasecmp(argv[1], "shun"))
        action = trace_shun_func;
    else if (!irccasecmp(argv[1], "kill"))
        action = trace_kill_func;
    else if (!irccasecmp(argv[1], "gag"))
        action = trace_gag_func;
    else if (!irccasecmp(argv[1], "svsjoin"))
        action = trace_svsjoin_func;
    else if (!irccasecmp(argv[1], "svspart"))
        action = trace_svspart_func;
    else if (!irccasecmp(argv[1], "version"))
        action = trace_version_func;
    else if (!irccasecmp(argv[1], "mark"))
        action = trace_mark_func;
    else {
        reply("OSMSG_BAD_ACTION", argv[1]);
        return 0;
    }

    if (user->handle_info->opserv_level < subcmd->min_opserv_level) {
        reply("OSMSG_LEVEL_TOO_LOW");
        return 0;
    }

    das.dict = NULL;
    das.source = user;
    das.destination = cmd->parent->bot;
    das.discrim = opserv_discrim_create(user, cmd->parent->bot, argc-2, argv+2, 1);
    if (!das.discrim)
        return 0;

    if (action == trace_print_func)
    {
        reply("OSMSG_USER_SEARCH_RESULTS");
        reply("OSMSG_USER_SEARCH_BAR");
        reply("OSMSG_USER_SEARCH_HEADER");
        reply("OSMSG_USER_SEARCH_BAR");
    }
    else if (action == trace_count_func)
        das.discrim->limit = INT_MAX;
    else if ((action == trace_gline_func) && !das.discrim->duration)
        das.discrim->duration = opserv_conf.block_gline_duration;
    else if ((action == trace_shun_func) && !das.discrim->duration)
        das.discrim->duration = opserv_conf.block_shun_duration;
    else if (action == trace_domains_func) {
        das.dict = dict_new();
        dict_set_free_data(das.dict, free);
        dict_set_free_keys(das.dict, free);
        das.disp_limit = das.discrim->limit;
        das.discrim->limit = INT_MAX;
    }

    if (action == trace_svsjoin_func && !das.discrim->chantarget) {
        reply("OSMSG_SVSJOIN_NO_TARGET");
        ret = 0;
    }
    else if (action == trace_svspart_func && !das.discrim->chantarget) {
        reply("OSMSG_SVSPART_NO_TARGET");
        ret = 0;
    }
    else if (action == trace_mark_func && !das.discrim->mark) {
        reply("OSMSG_MARK_NO_MARK");
        ret = 0;
    }
    else {
        matches = opserv_discrim_search(das.discrim, action, &das);

        if (action == trace_domains_func)
            dict_foreach(das.dict, opserv_show_hostinfo, &das);

        if (matches)
        {
            if(action == trace_print_func)
                reply("OSMSG_USER_SEARCH_COUNT_BAR", matches);
            else
                reply("OSMSG_USER_SEARCH_COUNT", matches);
        }
        else
                reply("MSG_NO_MATCHES");
    }

    if (das.discrim->channel)
        UnlockChannel(das.discrim->channel);
    free(das.discrim->reason);

    if(das.discrim->has_regex_nick)
      regfree(&das.discrim->regex_nick);
    if(das.discrim->has_regex_ident)
      regfree(&das.discrim->regex_ident);
    if(das.discrim->has_regex_host)
      regfree(&das.discrim->regex_host);
    if(das.discrim->has_regex_info)
      regfree(&das.discrim->regex_info);
    if(das.discrim->has_regex_version)
        regfree(&das.discrim->regex_version);

    free(das.discrim);
    dict_delete(das.dict);
    return ret;
}

typedef void (*cdiscrim_search_func)(struct chanNode *match, void *data, struct userNode *bot);

typedef struct channel_discrim {
    char *name, *topic;

    unsigned int min_users, max_users;
    time_t min_ts, max_ts;
    unsigned int limit;
} *cdiscrim_t;

static cdiscrim_t opserv_cdiscrim_create(struct userNode *user, struct userNode *bot, unsigned int argc, char *argv[]);
static unsigned int opserv_cdiscrim_search(cdiscrim_t discrim, cdiscrim_search_func dsf, void *data, struct userNode *bot);

static time_t
smart_parse_time(const char *str) {
    /* If an interval-style string is given, treat as time before now.
     * If it's all digits, treat directly as a Unix timestamp. */
    return str[strspn(str, "0123456789")] ? (time_t)(now - ParseInterval(str)) : (time_t)atoi(str);
}

static cdiscrim_t
opserv_cdiscrim_create(struct userNode *user, struct userNode *bot, unsigned int argc, char *argv[])
{
    cdiscrim_t discrim;
    unsigned int i;

    discrim = calloc(1, sizeof(*discrim));
    discrim->limit = 25;

    for (i = 0; i < argc; i++) {
        /* Assume all criteria require arguments. */
        if (i == (argc - 1)) {
            send_message(user, bot, "MSG_MISSING_PARAMS", argv[i]);
            return NULL;
        }

        if (!irccasecmp(argv[i], "name"))
            discrim->name = argv[++i];
        else if (!irccasecmp(argv[i], "topic"))
            discrim->topic = argv[++i];
        else if (!irccasecmp(argv[i], "users")) {
            const char *cmp = argv[++i];
            if (cmp[0] == '<') {
                if (cmp[1] == '=')
                    discrim->max_users = strtoul(cmp+2, NULL, 0);
                else
                    discrim->max_users = strtoul(cmp+1, NULL, 0) - 1;
            } else if (cmp[0] == '=') {
                discrim->min_users = discrim->max_users = strtoul(cmp+1, NULL, 0);
            } else if (cmp[0] == '>') {
                if (cmp[1] == '=')
                    discrim->min_users = strtoul(cmp+2, NULL, 0);
                else
                    discrim->min_users = strtoul(cmp+1, NULL, 0) + 1;
            } else {
                discrim->min_users = strtoul(cmp+2, NULL, 0);
            }
        } else if (!irccasecmp(argv[i], "timestamp")) {
            const char *cmp = argv[++i];
            if (cmp[0] == '<') {
                if (cmp[1] == '=')
                    discrim->max_ts = smart_parse_time(cmp+2);
                else
                    discrim->max_ts = smart_parse_time(cmp+1)-1;
            } else if (cmp[0] == '=') {
                discrim->min_ts = discrim->max_ts = smart_parse_time(cmp+1);
            } else if (cmp[0] == '>') {
                if (cmp[1] == '=')
                    discrim->min_ts = smart_parse_time(cmp+2);
                else
                    discrim->min_ts = smart_parse_time(cmp+1)+1;
            } else {
                discrim->min_ts = smart_parse_time(cmp);
            }
        } else if (!irccasecmp(argv[i], "limit")) {
            discrim->limit = strtoul(argv[++i], NULL, 10);
        } else {
            send_message(user, bot, "MSG_INVALID_CRITERIA", argv[i]);
            goto fail;
        }
    }

    if (discrim->name && !strcmp(discrim->name, "*"))
        discrim->name = 0;
    if (discrim->topic && !strcmp(discrim->topic, "*"))
        discrim->topic = 0;

    return discrim;
  fail:
    free(discrim);
    return NULL;
}

static int
cdiscrim_match(cdiscrim_t discrim, struct chanNode *chan)
{
    if ((discrim->name && !match_ircglob(chan->name, discrim->name)) ||
        (discrim->topic && !match_ircglob(chan->topic, discrim->topic)) ||
        (discrim->min_users && chan->members.used < discrim->min_users) ||
        (discrim->max_users && chan->members.used > discrim->max_users) ||
        (discrim->min_ts && chan->timestamp < discrim->min_ts) ||
            (discrim->max_ts && chan->timestamp > discrim->max_ts)) {
        return 0;
    }
    return 1;
}

static unsigned int opserv_cdiscrim_search(cdiscrim_t discrim, cdiscrim_search_func dsf, void *data, struct userNode *bot)
{
    unsigned int count = 0;
    dict_iterator_t it, next;

    for (it = dict_first(channels); it && count < discrim->limit ; it = next) {
        struct chanNode *chan = iter_data(it);

        /* Hold on to the next channel in case we decide to
           add actions that destructively modify the channel. */
        next = iter_next(it);
        if ((chan->members.used > 0) && cdiscrim_match(discrim, chan)) {
            dsf(chan, data, bot);
            count++;
        }
    }

    return count;
}

void channel_count(UNUSED_ARG(struct chanNode *channel), UNUSED_ARG(void *data), UNUSED_ARG(struct userNode *bot))
{
}

void channel_print(struct chanNode *channel, void *data, struct userNode *bot)
{
    char modes[MAXLEN];
    irc_make_chanmode(channel, modes);
    send_message(data, bot, "OSMSG_CSEARCH_CHANNEL_INFO", channel->name, channel->members.used, modes, channel->topic);
}

static MODCMD_FUNC(cmd_csearch)
{
    cdiscrim_t discrim;
    unsigned int matches;
    cdiscrim_search_func action;
    struct svccmd *subcmd;
    char buf[MAXLEN];

    if (!irccasecmp(argv[1], "count"))
        action = channel_count;
    else if (!irccasecmp(argv[1], "print"))
        action = channel_print;
    else {
        reply("OSMSG_BAD_ACTION", argv[1]);
        return 0;
    }

    sprintf(buf, "%s %s", argv[0], argv[0]);
    if ((subcmd = dict_find(opserv_service->commands, buf, NULL))
        && !svccmd_can_invoke(user, opserv_service->bot, subcmd, channel, SVCCMD_NOISY)) {
        return 0;
    }

    discrim = opserv_cdiscrim_create(user, cmd->parent->bot, argc - 2, argv + 2);
    if (!discrim)
        return 0;

    if (action == channel_print)
        reply("OSMSG_CHANNEL_SEARCH_RESULTS");
    else if (action == channel_count)
        discrim->limit = INT_MAX;

    matches = opserv_cdiscrim_search(discrim, action, user, cmd->parent->bot);

    if (matches)
        reply("MSG_MATCH_COUNT", matches);
    else
        reply("MSG_NO_MATCHES");

    free(discrim);
    return 1;
}

static MODCMD_FUNC(cmd_gsync)
{
    struct server *src;
    if (argc > 1) {
        src = GetServerH(argv[1]);
        if (!src) {
            reply("MSG_SERVER_UNKNOWN", argv[1]);
            return 0;
        }
    } else {
        src = self->uplink;
    }
    irc_stats(cmd->parent->bot, src, 'G');
    reply("OSMSG_GSYNC_RUNNING", src->name);
    return 1;
}

static MODCMD_FUNC(cmd_ssync)
{
    struct server *src;
    if (argc > 1) {
        src = GetServerH(argv[1]);
        if (!src) {
            reply("MSG_SERVER_UNKNOWN", argv[1]);
            return 0;
        }
    } else {
        src = self->uplink;
    }
    irc_stats(cmd->parent->bot, src, 'S');
    reply("OSMSG_SSYNC_RUNNING", src->name);
    return 1;
}

struct gline_extra {
    struct userNode *user;
    struct string_list *glines;
    struct userNode *bot;
};

static void
gtrace_print_func(struct gline *gline, void *extra)
{
    struct gline_extra *xtra = extra;
    char *when_text, set_text[20];
    strftime(set_text, sizeof(set_text), "%Y-%m-%d", localtime(&gline->issued));
    when_text = asctime(localtime(&gline->expires));
    when_text[strlen(when_text)-1] = 0; /* strip lame \n */
    send_message(xtra->user, xtra->bot, "OSMSG_GTRACE_FORMAT", gline->target, set_text, gline->issuer, when_text, gline->reason);
}

static void
gtrace_count_func(UNUSED_ARG(struct gline *gline), UNUSED_ARG(void *extra))
{
}

static void
gtrace_ungline_func(struct gline *gline, void *extra)
{
    struct gline_extra *xtra = extra;
    string_list_append(xtra->glines, strdup(gline->target));
}

static MODCMD_FUNC(cmd_gtrace)
{
    struct gline_discrim *discrim;
    gline_search_func action;
    unsigned int matches, nn;
    struct gline_extra extra;
    struct svccmd *subcmd;
    char buf[MAXLEN];

    if (!irccasecmp(argv[1], "print"))
        action = gtrace_print_func;
    else if (!irccasecmp(argv[1], "count"))
        action = gtrace_count_func;
    else if (!irccasecmp(argv[1], "ungline"))
        action = gtrace_ungline_func;
    else {
        reply("OSMSG_BAD_ACTION", argv[1]);
        return 0;
    }
    sprintf(buf, "%s %s", argv[0], argv[0]);
    if ((subcmd = dict_find(opserv_service->commands, buf, NULL))
        && !svccmd_can_invoke(user, opserv_service->bot, subcmd, channel, SVCCMD_NOISY)) {
        return 0;
    }

    discrim = gline_discrim_create(user, cmd->parent->bot, argc-2, argv+2);
    if (!discrim)
        return 0;

    if (action == gtrace_print_func)
        reply("OSMSG_GLINE_SEARCH_RESULTS");
    else if (action == gtrace_count_func)
        discrim->limit = INT_MAX;

    extra.user = user;
    extra.glines = alloc_string_list(4);
    extra.bot = cmd->parent->bot;
    matches = gline_discrim_search(discrim, action, &extra);

    if (action == gtrace_ungline_func)
        for (nn=0; nn<extra.glines->used; nn++)
            gline_remove(extra.glines->list[nn], 1);
    free_string_list(extra.glines);

    if (matches)
        reply("MSG_MATCH_COUNT", matches);
    else
        reply("MSG_NO_MATCHES");
    free(discrim->alt_target_mask);
    free(discrim);
    return 1;
}

struct shun_extra {
    struct userNode *user;
    struct string_list *shuns;
    struct userNode *bot;
};

static void
strace_print_func(struct shun *shun, void *extra)
{
    struct shun_extra *xtra = extra;
    char *when_text, set_text[20];
    strftime(set_text, sizeof(set_text), "%Y-%m-%d", localtime(&shun->issued));
    when_text = asctime(localtime(&shun->expires));
    when_text[strlen(when_text)-1] = 0; /* strip lame \n */
    send_message(xtra->user, xtra->bot, "OSMSG_STRACE_FORMAT", shun->target, set_text, shun->issuer, when_text, shun->reason);
}

static void
strace_count_func(UNUSED_ARG(struct shun *shun), UNUSED_ARG(void *extra))
{
}

static void
strace_unshun_func(struct shun *shun, void *extra)
{
    struct shun_extra *xtra = extra;
    string_list_append(xtra->shuns, strdup(shun->target));
}

static MODCMD_FUNC(cmd_strace)
{
    struct shun_discrim *discrim;
    shun_search_func action;
    unsigned int matches, nn;
    struct shun_extra extra;
    struct svccmd *subcmd;
    char buf[MAXLEN];

    if (!irccasecmp(argv[1], "print"))
        action = strace_print_func;
    else if (!irccasecmp(argv[1], "count"))
        action = strace_count_func;
    else if (!irccasecmp(argv[1], "unshun"))
        action = strace_unshun_func;
    else {
        reply("OSMSG_BAD_ACTION", argv[1]);
        return 0;
    }
    sprintf(buf, "%s %s", argv[0], argv[0]);
    if ((subcmd = dict_find(opserv_service->commands, buf, NULL))
        && !svccmd_can_invoke(user, opserv_service->bot, subcmd, channel, SVCCMD_NOISY)) {
        return 0;
    }

    discrim = shun_discrim_create(user, cmd->parent->bot, argc-2, argv+2);
    if (!discrim)
        return 0;

    if (action == strace_print_func)
        reply("OSMSG_SHUN_SEARCH_RESULTS");
    else if (action == strace_count_func)
        discrim->limit = INT_MAX;

    extra.user = user;
    extra.shuns = alloc_string_list(4);
    extra.bot = cmd->parent->bot;
    matches = shun_discrim_search(discrim, action, &extra);

    if (action == strace_unshun_func)
        for (nn=0; nn<extra.shuns->used; nn++)
            shun_remove(extra.shuns->list[nn], 1);
    free_string_list(extra.shuns);

    if (matches)
        reply("MSG_MATCH_COUNT", matches);
    else
        reply("MSG_NO_MATCHES");
    free(discrim->alt_target_mask);
    free(discrim);
    return 1;
}

static int
alert_check_user(const char *key, void *data, void *extra)
{
    struct opserv_user_alert *alert = data;
    struct userNode *user = extra;

    if (!discrim_match(alert->discrim, user))
        return 0;

    if ((alert->reaction != REACT_NOTICE)
        && IsOper(user)
        && !alert->discrim->match_opers) {
        return 0;
    }

    /* The user matches the alert criteria, so trigger the reaction. */
    if (alert->discrim->option_log)
        log_module(OS_LOG, LOG_INFO, "Alert %s triggered by user %s!%s@%s (%s).", key, user->nick, user->ident, user->hostname, alert->discrim->reason);

    alert->last = now;

    /* Return 1 to halt alert matching, such as when killing the user
       that triggered the alert. */
    switch (alert->reaction) {
    case REACT_KILL:
        DelUser(user, opserv, 1, alert->discrim->reason);
        return 1;
    case REACT_GLINE:
        opserv_block(user, alert->owner, alert->discrim->reason, alert->discrim->duration, alert->discrim->silent);
        return 1;
    case REACT_SHUN:
        opserv_shun(user, alert->owner, alert->discrim->reason, alert->discrim->duration);
        return 1;
    case REACT_SVSJOIN:
        opserv_svsjoin(user, alert->owner, alert->discrim->reason, alert->discrim->chantarget, alert->discrim->checkrestrictions);
        break;
    case REACT_SVSPART:
        opserv_svspart(user, alert->owner, alert->discrim->reason, alert->discrim->chantarget);
        break;
    case REACT_VERSION:
        /* Don't auto-version a user who we already have a version on, because the version reply itself
         * re-triggers this check... 
         * TODO: maybe safer if we didn't even check react_version type alerts for the 2nd check?
         *       sort of like we only look at channel alerts on join. -Rubin
         */
        if(!user->version_reply)
            opserv_version(user);
        break;
    case REACT_MARK:
        opserv_mark(user, alert->owner, alert->discrim->reason, alert->discrim->mark);
        break;
    default:
        log_module(OS_LOG, LOG_ERROR, "Invalid reaction type %d for alert %s.", alert->reaction, key);
        /* fall through to REACT_NOTICE case */
    case REACT_NOTICE:
        opserv_alert("Alert $b%s$b triggered by user $b%s$b!%s@%s (%s).", key, user->nick, user->ident, user->hostname, alert->discrim->reason);
        break;
    case REACT_TRACK:
#ifdef HAVE_TRACK
        opserv_alert("Alert $b%s$b triggered by user $b%s$b!%s@%s (%s) (Tracking).", key, user->nick, user->ident, user->hostname, alert->discrim->reason);
	add_track_user(user);
#endif
	break;
    }
    return 0;
}

static void
opserv_alert_check_nick(struct userNode *user, UNUSED_ARG(const char *old_nick))
{
    struct gag_entry *gag;
    dict_foreach(opserv_nick_based_alerts, alert_check_user, user);
    /* Gag them if appropriate (and only if). */
    user->modes &= ~FLAGS_GAGGED;
    for (gag = gagList; gag; gag = gag->next) {
        if (user_matches_glob(user, gag->mask, MATCH_USENICK)) {
            gag_helper_func(user, NULL);
            break;
        }
    }
}

static void
opserv_staff_alert(struct userNode *user, UNUSED_ARG(struct handle_info *old_handle))
{
    const char *type;

    if (!opserv_conf.staff_auth_channel
        || user->uplink->burst
        || !user->handle_info)
        return;
    else if (user->handle_info->opserv_level)
        type = "OPER";
    else if (IsNetworkHelper(user))
        type = "NETWORK HELPER";
    else if (IsSupportHelper(user))
        type = "SUPPORT HELPER";
    else
        return;

    if (irc_in_addr_is_valid(user->ip))
        send_channel_notice(opserv_conf.staff_auth_channel, opserv, IDENT_FORMAT" authed to %s account %s", IDENT_DATA(user), type, user->handle_info->handle);
    else
        send_channel_notice(opserv_conf.staff_auth_channel, opserv, "%s [%s@%s] authed to %s account %s", user->nick, user->ident, user->hostname, type, user->handle_info->handle);
}

static MODCMD_FUNC(cmd_log)
{
    struct logSearch *discrim;
    unsigned int matches;
    struct logReport report;

    discrim = log_discrim_create(cmd->parent->bot, user, argc, argv);
    if (!discrim)
        return 0;

    reply("OSMSG_LOG_SEARCH_RESULTS");
    report.reporter = opserv;
    report.user = user;
    matches = log_entry_search(discrim, log_report_entry, &report);

    if (matches)
        reply("MSG_MATCH_COUNT", matches);
    else
        reply("MSG_NO_MATCHES");

    free(discrim);
    return 1;
}

static int
gag_helper_func(struct userNode *match, UNUSED_ARG(void *extra))
{
    if (IsOper(match) || IsLocal(match))
        return 0;
    match->modes |= FLAGS_GAGGED;
    return 0;
}

static MODCMD_FUNC(cmd_gag)
{
    struct gag_entry *gag;
    unsigned int gagged;
    unsigned long duration;
    char *reason;

    reason = unsplit_string(argv + 3, argc - 3, NULL);

    if (!is_ircmask(argv[1])) {
        reply("OSMSG_INVALID_IRCMASK", argv[1]);
        return 0;
    }

    for (gag = gagList; gag; gag = gag->next)
        if (match_ircglobs(gag->mask, argv[1]))
            break;

    if (gag) {
        reply("OSMSG_REDUNDANT_GAG", argv[1]);
        return 0;
    }

    duration = ParseInterval(argv[2]);
    gagged = gag_create(argv[1], user->handle_info->handle, reason, (duration?now+duration:0));

    if (gagged)
        reply("OSMSG_GAG_APPLIED", argv[1], gagged);
    else
        reply("OSMSG_GAG_ADDED", argv[1]);
    return 1;
}

static int
ungag_helper_func(struct userNode *match, UNUSED_ARG(void *extra))
{
    match->modes &= ~FLAGS_GAGGED;
    return 0;
}

static MODCMD_FUNC(cmd_ungag)
{
    struct gag_entry *gag;
    unsigned int ungagged;

    for (gag = gagList; gag; gag = gag->next)
        if (!strcmp(gag->mask, argv[1]))
            break;

    if (!gag) {
        reply("OSMSG_GAG_NOT_FOUND", argv[1]);
        return 0;
    }

    timeq_del(gag->expires, gag_expire, gag, 0);
    ungagged = gag_free(gag);

    if (ungagged)
        reply("OSMSG_UNGAG_APPLIED", argv[1], ungagged);
    else
        reply("OSMSG_UNGAG_ADDED", argv[1]);
    return 1;
}

static MODCMD_FUNC(cmd_addalert)
{
    opserv_alert_reaction reaction;
    struct svccmd *subcmd;
    const char *name;
    char buf[MAXLEN];

    name = argv[1];
    sprintf(buf, "addalert %s", argv[2]);
    if (!(subcmd = dict_find(opserv_service->commands, buf, NULL))) {
        reply("OSMSG_UNKNOWN_REACTION", argv[2]);
        return 0;
    }
    if (!irccasecmp(argv[2], "notice"))
        reaction = REACT_NOTICE;
    else if (!irccasecmp(argv[2], "kill"))
        reaction = REACT_KILL;
    else if (!irccasecmp(argv[2], "gline"))
        reaction = REACT_GLINE;
    else if (!irccasecmp(argv[2], "track")) {
#ifndef HAVE_TRACK
        reply("OSMSG_TRACK_DISABLED");
        return 0;
#else
        reaction = REACT_TRACK;
#endif
    } else if (!irccasecmp(argv[2], "shun"))
        reaction = REACT_SHUN;
    else if(!irccasecmp(argv[2], "svsjoin")) 
        reaction = REACT_SVSJOIN;
    else if(!irccasecmp(argv[2], "svspart")) 
        reaction = REACT_SVSPART;
    else if(!irccasecmp(argv[2], "version"))
        reaction = REACT_VERSION;
    else if(!irccasecmp(argv[2], "mark"))
        reaction = REACT_MARK;
    else {
        reply("OSMSG_UNKNOWN_REACTION", argv[2]);
        return 0;
    }
    if (!svccmd_can_invoke(user, opserv_service->bot, subcmd, channel, SVCCMD_NOISY)
        || !opserv_add_user_alert(user, name, reaction, unsplit_string(argv + 3, argc - 3, NULL), 0)) {
        reply("OSMSG_ALERT_ADD_FAILED");
        return 0;
    }
    reply("OSMSG_ADDED_ALERT", name);
    return 1;
}

static MODCMD_FUNC(cmd_delalert)
{
    unsigned int i;
    for (i=1; i<argc; i++) {
        dict_remove(opserv_nick_based_alerts, argv[i]);
        dict_remove(opserv_channel_alerts, argv[i]);
        if (dict_remove(opserv_user_alerts, argv[i]))
            reply("OSMSG_REMOVED_ALERT", argv[i]);
        else
            reply("OSMSG_NO_SUCH_ALERT", argv[i]);
    }
    return 1;
}

static void
opserv_conf_read(void)
{
    struct chanNode *chan;
    unsigned int i;
    struct record_data *rd;
    dict_t conf_node, child;
    const char *str, *str2;
    struct policer_params *pp;
    dict_iterator_t it;

    rd = conf_get_node(OPSERV_CONF_NAME);
    if (!rd || rd->type != RECDB_OBJECT) {
        log_module(OS_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", OPSERV_CONF_NAME);
        return;
    }
    conf_node = rd->d.object;
    str = database_get_data(conf_node, KEY_DEBUG_CHANNEL, RECDB_QSTRING);
    if (opserv && str) {
        str2 = database_get_data(conf_node, KEY_DEBUG_CHANNEL_MODES, RECDB_QSTRING);
        if (!str2)
            str2 = "+tinms";
        opserv_conf.debug_channel = AddChannel(str, now, str2, NULL, NULL);
        AddChannelUser(opserv, opserv_conf.debug_channel)->modes |= MODE_CHANOP;
    } else {
        opserv_conf.debug_channel = NULL;
    }
    str = database_get_data(conf_node, KEY_ALERT_CHANNEL, RECDB_QSTRING);
    if (opserv && str) {
        str2 = database_get_data(conf_node, KEY_ALERT_CHANNEL_MODES, RECDB_QSTRING);
        if (!str2)
            str2 = "+tns";
        opserv_conf.alert_channel = AddChannel(str, now, str2, NULL, NULL);
        AddChannelUser(opserv, opserv_conf.alert_channel)->modes |= MODE_CHANOP;
    } else {
        opserv_conf.alert_channel = NULL;
    }
    str = database_get_data(conf_node, KEY_STAFF_AUTH_CHANNEL, RECDB_QSTRING);
    if (opserv && str) {
        str2 = database_get_data(conf_node, KEY_STAFF_AUTH_CHANNEL_MODES, RECDB_QSTRING);
        if (!str2)
            str2 = "+timns";
        opserv_conf.staff_auth_channel = AddChannel(str, now, str2, NULL, NULL);
        AddChannelUser(opserv, opserv_conf.staff_auth_channel)->modes |= MODE_CHANOP;
    } else {
        opserv_conf.staff_auth_channel = NULL;
    }

    str = database_get_data(conf_node, KEY_ADMIN_LEVEL, RECDB_QSTRING);
    opserv_conf.admin_level = str ? strtoul(str, NULL, 0): 800;

    str = database_get_data(conf_node, KEY_SILENT_LEVEL, RECDB_QSTRING);
    opserv_conf.silent_level = str ? strtoul(str, NULL, 0): 700;

    str = database_get_data(conf_node, KEY_UNTRUSTED_MAX, RECDB_QSTRING);
    opserv_conf.untrusted_max = str ? strtoul(str, NULL, 0) : 5;
    str = database_get_data(conf_node, KEY_PURGE_LOCK_DELAY, RECDB_QSTRING);
    opserv_conf.purge_lock_delay = str ? strtoul(str, NULL, 0) : 60;
    str = database_get_data(conf_node, KEY_JOIN_FLOOD_MODERATE, RECDB_QSTRING);
    opserv_conf.join_flood_moderate = str ? strtoul(str, NULL, 0) : 1;
    str = database_get_data(conf_node, KEY_JOIN_FLOOD_MODERATE_THRESH, RECDB_QSTRING);
    opserv_conf.join_flood_moderate_threshold = str ? strtoul(str, NULL, 0) : 50;
    str = database_get_data(conf_node, KEY_NICK, RECDB_QSTRING);
    if (opserv && str)
        NickChange(opserv, str, 0);

    str = database_get_data(conf_node, KEY_CLONE_GLINE_DURATION, RECDB_QSTRING);
    opserv_conf.clone_gline_duration = str ? ParseInterval(str) : 3600;
    str = database_get_data(conf_node, KEY_BLOCK_GLINE_DURATION, RECDB_QSTRING);
    opserv_conf.block_gline_duration = str ? ParseInterval(str) : 3600;

    free_string_list(autojoin_channels);
    autojoin_channels = database_get_data(conf_node, KEY_AUTOJOIN_CHANNELS, RECDB_STRING_LIST);

    if(autojoin_channels)
        autojoin_channels = string_list_copy(autojoin_channels);

    if (autojoin_channels && opserv) {
        for (i = 0; i < autojoin_channels->used; i++) {
            chan = AddChannel(autojoin_channels->list[i], now, "+nt", NULL, NULL);
            AddChannelUser(opserv, chan)->modes |= MODE_CHANOP;
        }
    }

    str = database_get_data(conf_node, KEY_BLOCK_SHUN_DURATION, RECDB_QSTRING);
    opserv_conf.block_shun_duration = str ? ParseInterval(str) : 3600;

    if (!opserv_conf.join_policer_params)
        opserv_conf.join_policer_params = policer_params_new();
    policer_params_set(opserv_conf.join_policer_params, "size", "20");
    policer_params_set(opserv_conf.join_policer_params, "drain-rate", "1");
    if ((child = database_get_data(conf_node, KEY_JOIN_POLICER, RECDB_OBJECT)))
        dict_foreach(child, set_policer_param, opserv_conf.join_policer_params);

    for (it = dict_first(channels); it; it = iter_next(it)) {
        struct chanNode *cNode = iter_data(it);
        cNode->join_policer.params = opserv_conf.join_policer_params;
    }

    if (opserv_conf.new_user_policer.params)
        pp = opserv_conf.new_user_policer.params;
    else
        pp = opserv_conf.new_user_policer.params = policer_params_new();
    policer_params_set(pp, "size", "200");
    policer_params_set(pp, "drain-rate", "3");
    if ((child = database_get_data(conf_node, KEY_NEW_USER_POLICER, RECDB_OBJECT)))
        dict_foreach(child, set_policer_param, pp);

    /* Defcon configuration */
    DefCon[0] = 0;
    str = database_get_data(conf_node, KEY_DEFCON1, RECDB_QSTRING);
    DefCon[1] = str ? atoi(str) : 415;
    str = database_get_data(conf_node, KEY_DEFCON2, RECDB_QSTRING);
    DefCon[2] = str ? atoi(str) : 159;
    str = database_get_data(conf_node, KEY_DEFCON3, RECDB_QSTRING);
    DefCon[3] = str ? atoi(str) : 31;
    str = database_get_data(conf_node, KEY_DEFCON4, RECDB_QSTRING);
    DefCon[4] = str? atoi(str) : 23;
    DefCon[5] = 0;

    str = database_get_data(conf_node, KEY_DEFCON_LEVEL, RECDB_QSTRING);
    DefConLevel = str ? atoi(str) : 5;

    str = database_get_data(conf_node, KEY_DEFCON_CHANMODES, RECDB_QSTRING);
    DefConChanModes = str ? strdup(str) : "+r";

    str = database_get_data(conf_node, KEY_DEFCON_SESSION_LIMIT, RECDB_QSTRING);
    DefConSessionLimit = str ? atoi(str) : 2;

    str = database_get_data(conf_node, KEY_DEFCON_TIMEOUT, RECDB_QSTRING);
    DefConTimeOut = str ? ParseInterval(str) : 900;

    str = database_get_data(conf_node, KEY_DEFCON_GLINE_DURATION, RECDB_QSTRING);
    DefConGlineExpire = str ? ParseInterval(str) : 300;

    str = database_get_data(conf_node, KEY_DEFCON_GLOBAL, RECDB_QSTRING);
    GlobalOnDefcon = str ? atoi(str) : 0;

    str = database_get_data(conf_node, KEY_DEFCON_GLOBAL_MORE, RECDB_QSTRING);
    GlobalOnDefconMore = str ? atoi(str) : 0;

    str = database_get_data(conf_node, KEY_DEFCON_MESSAGE, RECDB_QSTRING);
    DefConMessage = str ? strdup(str) : "Put your message to send your users here. Dont forget to uncomment GlobalOnDefconMore";

    str = database_get_data(conf_node, KEY_DEFCON_OFF_MESSAGE, RECDB_QSTRING);
    DefConOffMessage = str? strdup(str) : "Services are now back to normal, sorry for any inconvenience";

    str = database_get_data(conf_node, KEY_DEFCON_GLINE_REASON, RECDB_QSTRING);
    DefConGlineReason = str ? strdup(str) : "This network is currently not accepting connections, please try again later";
}

/* lame way to export opserv_conf value to nickserv.c ... */
unsigned int 
opserv_conf_admin_level()
{
    return(opserv_conf.admin_level);
}

static void
opserv_db_init(void) {
    /* set up opserv_trusted_hosts dict */
    dict_delete(opserv_trusted_hosts);
    opserv_trusted_hosts = dict_new();
    dict_set_free_data(opserv_trusted_hosts, free_trusted_host);

    opserv_routing_plan_options = dict_new();

    opserv_routing_plans = dict_new();
    dict_set_free_data(opserv_routing_plans, free_routing_plan);
    /* set up opserv_chan_warn dict */

/* alert trace notice channel #x replaces warnings
    dict_delete(opserv_chan_warn);
    opserv_chan_warn = dict_new();
    dict_set_free_keys(opserv_chan_warn, free);
    dict_set_free_data(opserv_chan_warn, free);
*/
    /* set up opserv_user_alerts */
    dict_delete(opserv_channel_alerts);
    opserv_channel_alerts = dict_new();
    dict_delete(opserv_nick_based_alerts);
    opserv_nick_based_alerts = dict_new();
    dict_delete(opserv_user_alerts);
    opserv_user_alerts = dict_new();
    dict_set_free_keys(opserv_user_alerts, free);
    dict_set_free_data(opserv_user_alerts, opserv_free_user_alert);
    /* set up opserv_bad_words */
    free_string_list(opserv_bad_words);
    opserv_bad_words = alloc_string_list(4);
    /* and opserv_exempt_channels */
    dict_delete(opserv_exempt_channels);
    opserv_exempt_channels = dict_new();
    dict_set_free_keys(opserv_exempt_channels, free);
}

static void
opserv_db_cleanup(void)
{
    unsigned int nn;

/*    dict_delete(opserv_chan_warn); */
    dict_delete(opserv_reserved_nick_dict);
    free_string_list(opserv_bad_words);
    dict_delete(opserv_exempt_channels);
    dict_delete(opserv_trusted_hosts);
    unreg_del_user_func(opserv_user_cleanup);
    dict_delete(opserv_hostinfo_dict);
    dict_delete(opserv_nick_based_alerts);
    dict_delete(opserv_channel_alerts);
    dict_delete(opserv_user_alerts);
    for (nn=0; nn<ArrayLength(level_strings); ++nn)
        free(level_strings[nn]);
    while (gagList)
        gag_free(gagList);
    policer_params_delete(opserv_conf.join_policer_params);
    policer_params_delete(opserv_conf.new_user_policer.params);
}

void
init_opserv(const char *nick)
{
    OS_LOG = log_register_type("OpServ", "file:opserv.log");
    if (nick) {
        const char *modes = conf_get_data("services/opserv/modes", RECDB_QSTRING);
        opserv = AddService(nick, modes ? modes : NULL, "Oper Services", NULL);
    }
    conf_register_reload(opserv_conf_read);

    memset(level_strings, 0, sizeof(level_strings));
    opserv_module = module_register("OpServ", OS_LOG, "opserv.help", opserv_help_expand);
    opserv_define_func("ACCESS", cmd_access, 0, 0, 0);
    opserv_define_func("ADDALERT", cmd_addalert, 800, 0, 4);
    opserv_define_func("ADDALERT NOTICE", NULL, 0, 0, 0);
    opserv_define_func("ADDALERT SILENT", NULL, 900, 0, 0);
    opserv_define_func("ADDALERT GLINE", NULL, 900, 0, 0);
    opserv_define_func("ADDALERT SHUN", NULL, 900, 0, 0);
    opserv_define_func("ADDALERT TRACK", NULL, 900, 0, 0);
    opserv_define_func("ADDALERT KILL", NULL, 900, 0, 0);
    opserv_define_func("ADDALERT SVSJOIN", NULL, 999, 0, 0);
    opserv_define_func("ADDALERT SVSPART", NULL, 999, 0, 0);
    opserv_define_func("ADDALERT VERSION", NULL, 999, 0, 0);
    opserv_define_func("ADDALERT MARK", NULL, 999, 0, 0);
    opserv_define_func("ADDBAD", cmd_addbad, 800, 0, 2);
    opserv_define_func("ADDEXEMPT", cmd_addexempt, 800, 0, 2);
    opserv_define_func("ADDTRUST", cmd_addtrust, 800, 0, 5);
    opserv_define_func("BAN", cmd_ban, 100, 2, 2);
    opserv_define_func("BLOCK", cmd_block, 100, 0, 2);
    opserv_define_func("CHANINFO", cmd_chaninfo, 0, 3, 0);
    opserv_define_func("CLEARBANS", cmd_clearbans, 300, 2, 0);
    opserv_define_func("CLEARMODES", cmd_clearmodes, 400, 2, 0);
    opserv_define_func("CLONE", cmd_clone, 999, 0, 3);
    opserv_define_func("COLLIDE", cmd_collide, 800, 0, 5);
    opserv_define_func("CSEARCH", cmd_csearch, 100, 0, 3);
    opserv_define_func("CSEARCH COUNT", cmd_csearch, 0, 0, 0);
    opserv_define_func("CSEARCH PRINT", cmd_csearch, 0, 0, 0);
    opserv_define_func("DELALERT", cmd_delalert, 800, 0, 2);
    opserv_define_func("DELBAD", cmd_delbad, 800, 0, 2);
    opserv_define_func("DELEXEMPT", cmd_delexempt, 800, 0, 2);
    opserv_define_func("DELTRUST", cmd_deltrust, 800, 0, 2);
    opserv_define_func("DEOP", cmd_deop, 100, 2, 2);
    opserv_define_func("DEOPALL", cmd_deopall, 400, 2, 0);
    opserv_define_func("DEFCON", cmd_defcon, 900, 0, 0);
    opserv_define_func("DEHOP", cmd_dehop, 100, 2, 2);
    opserv_define_func("DEHOPALL", cmd_dehopall, 400, 2, 0);
    opserv_define_func("DEVOICEALL", cmd_devoiceall, 300, 2, 0);
    opserv_define_func("DIE", cmd_die, 900, 0, 2);
    opserv_define_func("DUMP", cmd_dump, 999, 0, 2);
    opserv_define_func("EDITTRUST", cmd_edittrust, 800, 0, 5);
    opserv_define_func("GAG", cmd_gag, 600, 0, 4);
    opserv_define_func("GLINE", cmd_gline, 600, 0, 4);
    opserv_define_func("GSYNC", cmd_gsync, 600, 0, 0);
    opserv_define_func("GTRACE", cmd_gtrace, 100, 0, 3);
    opserv_define_func("GTRACE COUNT", NULL, 0, 0, 0);
    opserv_define_func("GTRACE PRINT", NULL, 0, 0, 0);
    opserv_define_func("SBLOCK", cmd_sblock, 100, 0, 2);
    opserv_define_func("SHUN", cmd_shun, 600, 0, 4);
    opserv_define_func("SSYNC", cmd_ssync, 600, 0, 0);
    opserv_define_func("STRACE", cmd_strace, 100, 0, 3);
    opserv_define_func("STRACE COUNT", NULL, 0, 0, 0);
    opserv_define_func("STRACE PRINT", NULL, 0, 0, 0);
    opserv_define_func("INVITE", cmd_invite, 100, 2, 0);
    opserv_define_func("INVITEME", cmd_inviteme, 100, 0, 0);
    opserv_define_func("JOIN", cmd_join, 601, 0, 2);
    opserv_define_func("SVSNICK", cmd_svsnick, 999, 0, 3);
    opserv_define_func("SVSJOIN", cmd_svsjoin, 999, 0, 3);
    opserv_define_func("SVSPART", cmd_svspart, 999, 0, 3);
    opserv_define_func("JUMP", cmd_jump, 900, 0, 2);
    opserv_define_func("JUPE", cmd_jupe, 900, 0, 4);
    opserv_define_func("KICK", cmd_kick, 100, 2, 2);
    opserv_define_func("KICKALL", cmd_kickall, 400, 2, 0);
    opserv_define_func("KICKBAN", cmd_kickban, 100, 2, 2);
    opserv_define_func("KICKBANALL", cmd_kickbanall, 450, 2, 0);
    opserv_define_func("LOG", cmd_log, 900, 0, 2);
    opserv_define_func("MODE", cmd_mode, 100, 2, 2);
    opserv_define_func("MARK", cmd_mark, 900, 0, 3);
    opserv_define_func("OP", cmd_op, 100, 2, 2);
    opserv_define_func("OPALL", cmd_opall, 400, 2, 0);
    opserv_define_func("HOP", cmd_hop, 100, 2, 2);
    opserv_define_func("HOPALL", cmd_hopall, 400, 2, 0);
    opserv_define_func("MAP", cmd_stats_links, 0, 0, 0);
    opserv_define_func("PRIVSET", cmd_privset, 900, 0, 3);
    opserv_define_func("PART", cmd_part, 601, 0, 2);
    opserv_define_func("QUERY", cmd_query, 0, 0, 0);
    opserv_define_func("RAW", cmd_raw, 999, 0, 2);
    opserv_define_func("RECONNECT", cmd_reconnect, 900, 0, 0);
    opserv_define_func("REFRESHG", cmd_refreshg, 600, 0, 0);
    opserv_define_func("REFRESHS", cmd_refreshs, 600, 0, 0);
    opserv_define_func("REHASH", cmd_rehash, 900, 0, 0);
    opserv_define_func("REOPEN", cmd_reopen, 900, 0, 0);
    opserv_define_func("RESETMAX", cmd_resetmax, 900, 0, 0);
    opserv_define_func("RESERVE", cmd_reserve, 800, 0, 5);
    opserv_define_func("RESTART", cmd_restart, 900, 0, 2);
    opserv_define_func("ROUTING ADDPLAN", cmd_routing_addplan, 800, 0, 2);
    opserv_define_func("ROUTING DELPLAN", cmd_routing_delplan, 800, 0, 2);
    opserv_define_func("ROUTING ADDSERVER", cmd_routing_addserver, 800, 0, 4);
    opserv_define_func("ROUTING DELSERVER", cmd_routing_delserver, 800, 0, 3);
    opserv_define_func("ROUTING MAP", cmd_routing_map, 800, 0, 0);
    opserv_define_func("ROUTING SET", cmd_routing_set, 800, 0, 0);
    opserv_define_func("REROUTE", cmd_reroute, 800, 0, 2);
    opserv_define_func("SET", cmd_set, 900, 0, 3);
    opserv_define_func("SETTIME", cmd_settime, 901, 0, 0);
    opserv_define_func("STATS ALERTS", cmd_stats_alerts, 0, 0, 0);
    opserv_define_func("STATS BAD", cmd_stats_bad, 0, 0, 0);
    opserv_define_func("STATS GAGS", cmd_stats_gags, 0, 0, 0);
    opserv_define_func("STATS GLINES", cmd_stats_glines, 0, 0, 0);
    opserv_define_func("STATS SHUNS", cmd_stats_shuns, 0, 0, 0);
    opserv_define_func("STATS LINKS", cmd_stats_links, 0, 0, 0);
    opserv_define_func("STATS MAX", cmd_stats_max, 0, 0, 0);
    opserv_define_func("STATS NETWORK", cmd_stats_network, 0, 0, 0);
    opserv_define_func("STATS NETWORK2", cmd_stats_network2, 0, 0, 0);
    opserv_define_func("STATS RESERVED", cmd_stats_reserved, 0, 0, 0);
    opserv_define_func("STATS ROUTING", cmd_stats_routing_plans, 0, 0, 0);
    opserv_define_func("STATS TIMEQ", cmd_stats_timeq, 0, 0, 0);
    opserv_define_func("STATS TRUSTED", cmd_stats_trusted, 0, 0, 0);
    opserv_define_func("STATS UPLINK", cmd_stats_uplink, 0, 0, 0);
    opserv_define_func("STATS UPTIME", cmd_stats_uptime, 0, 0, 0);
/*    opserv_define_func("STATS WARN", cmd_stats_warn, 0, 0, 0); */
#if defined(WITH_MALLOC_X3) || defined(WITH_MALLOC_SLAB)
    opserv_define_func("STATS MEMORY", cmd_stats_memory, 0, 0, 0);
#endif
    opserv_define_func("TRACE", cmd_trace, 100, 0, 3);
    opserv_define_func("TRACE PRINT", NULL, 0, 0, 0);
    opserv_define_func("TRACE COUNT", NULL, 0, 0, 0);
    opserv_define_func("TRACE DOMAINS", NULL, 0, 0, 0);
    opserv_define_func("TRACE GLINE", NULL, 600, 0, 0);
    opserv_define_func("TRACE SHUN", NULL, 600, 0, 0);
    opserv_define_func("TRACE GAG", NULL, 600, 0, 0);
    opserv_define_func("TRACE KILL", NULL, 600, 0, 0);
    opserv_define_func("TRACE VERSION", NULL, 999, 0, 0);
    opserv_define_func("TRACE SVSJOIN", NULL, 999, 0, 0);
    opserv_define_func("TRACE SVSPART", NULL, 999, 0, 0);
    opserv_define_func("TRACE MARK", NULL, 999, 0, 0);
    opserv_define_func("UNBAN", cmd_unban, 100, 2, 2);
    opserv_define_func("UNGAG", cmd_ungag, 600, 0, 2);
    opserv_define_func("UNGLINE", cmd_ungline, 600, 0, 2);
    modcmd_register(opserv_module, "GTRACE UNGLINE", NULL, 0, 0, "template", "ungline", NULL);
    opserv_define_func("UNSHUN", cmd_unshun, 600, 0, 2);
    modcmd_register(opserv_module, "GTRACE UNSHUN", NULL, 0, 0, "template", "unshun", NULL);
    opserv_define_func("UNJUPE", cmd_unjupe, 900, 0, 2);
    opserv_define_func("UNRESERVE", cmd_unreserve, 800, 0, 2);
/*    opserv_define_func("UNWARN", cmd_unwarn, 800, 0, 0); */
    opserv_define_func("VOICEALL", cmd_voiceall, 300, 2, 0);
/*    opserv_define_func("WARN", cmd_warn, 800, 0, 2); */
    opserv_define_func("WHOIS", cmd_whois, 0, 0, 2);

    opserv_reserved_nick_dict = dict_new();
    opserv_hostinfo_dict = dict_new();

    dict_set_free_keys(opserv_hostinfo_dict, free);
    dict_set_free_data(opserv_hostinfo_dict, opserv_free_hostinfo);

    opserv_waiting_connections = dict_new();
    dict_set_free_data(opserv_waiting_connections, opserv_free_waiting_connection);

    reg_new_user_func(opserv_new_user_check);
    reg_nick_change_func(opserv_alert_check_nick);
    reg_del_user_func(opserv_user_cleanup);
    reg_new_channel_func(opserv_channel_check); 
    reg_del_channel_func(opserv_channel_delete);
    reg_join_func(opserv_join_check);
    reg_auth_func(opserv_staff_alert);
    reg_notice_func(opserv, opserv_notice_handler);

    opserv_db_init();
    saxdb_register("OpServ", opserv_saxdb_read, opserv_saxdb_write);
    if (nick)
    {
        opserv_service = service_register(opserv);
        opserv_service->trigger = '?';
    }

    /* start auto-routing system */
    /* this cant be done here, because the routing system isnt marked active yet. */
    /* reroute_timer(NULL); */

    /* start the karma timer, using the saved one if available */
    routing_karma_timer(dict_find(opserv_routing_plan_options, "KARMA_TIMER", NULL));

    reg_exit_func(opserv_db_cleanup);
    message_register_table(msgtab);
}
