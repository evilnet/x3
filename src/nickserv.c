/* nickserv.c - Nick/authentication service
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

#include "base64.h"
#include "chanserv.h"
#include "conf.h"
#include "config.h"
#include "global.h"
#include "modcmd.h"
#include "opserv.h" /* for gag_create(), opserv_bad_channel() */
#include "saxdb.h"
#include "mail.h"
#include "timeq.h"
#include "x3ldap.h"

#include <tre/regex.h>

#ifdef WITH_LDAP
#include <ldap.h>
#endif

#define NICKSERV_CONF_NAME "services/nickserv"

#define KEY_DISABLE_NICKS "disable_nicks"
#define KEY_DEFAULT_HOSTMASK "default_hostmask"
#define KEY_NICKS_PER_HANDLE "nicks_per_handle"
#define KEY_NICKS_PER_ACCOUNT "nicks_per_account"
#define KEY_PASSWORD_MIN_LENGTH "password_min_length"
#define KEY_PASSWORD_MIN_DIGITS "password_min_digits"
#define KEY_PASSWORD_MIN_UPPER "password_min_upper"
#define KEY_PASSWORD_MIN_LOWER "password_min_lower"
#define KEY_VALID_HANDLE_REGEX "valid_handle_regex"
#define KEY_VALID_ACCOUNT_REGEX "valid_account_regex"
#define KEY_VALID_NICK_REGEX "valid_nick_regex"
#define KEY_VALID_FAKEHOST_REGEX "valid_fakehost_regex"
#define KEY_DB_BACKUP_FREQ "db_backup_freq"
#define KEY_MODOPER_LEVEL "modoper_level"
#define KEY_SET_EPITHET_LEVEL "set_epithet_level"
#define KEY_SET_TITLE_LEVEL "set_title_level"
#define KEY_SET_FAKEHOST_LEVEL "set_fakehost_level"
#define KEY_DENIED_FAKEHOST_WORDS "denied_fakehost_words"
#define KEY_TITLEHOST_SUFFIX "titlehost_suffix"
#define KEY_AUTO_OPER "auto_oper"
#define KEY_AUTO_ADMIN "auto_admin"
#define KEY_AUTO_OPER_PRIVS "auto_oper_privs"
#define KEY_AUTO_ADMIN_PRIVS "auto_admin_privs"
#define KEY_FLAG_LEVELS "flag_levels"
#define KEY_HANDLE_EXPIRE_FREQ	"handle_expire_freq"
#define KEY_ACCOUNT_EXPIRE_FREQ "account_expire_freq"
#define KEY_HANDLE_EXPIRE_DELAY	"handle_expire_delay"
#define KEY_NICK_EXPIRE_FREQ "nick_expire_freq"
#define KEY_NICK_EXPIRE_DELAY "nick_expire_delay"
#define KEY_ACCOUNT_EXPIRE_DELAY "account_expire_delay"
#define KEY_NOCHAN_HANDLE_EXPIRE_DELAY "nochan_handle_expire_delay"
#define KEY_NOCHAN_ACCOUNT_EXPIRE_DELAY "nochan_account_expire_delay"
#define KEY_DICT_FILE "dict_file"
#define KEY_NICK "nick"
#define KEY_LANGUAGE "language"
#define KEY_AUTOGAG_ENABLED "autogag_enabled"
#define KEY_AUTOGAG_DURATION "autogag_duration"
#define KEY_AUTH_POLICER "auth_policer"
#define KEY_EMAIL_VISIBLE_LEVEL "email_visible_level"
#define KEY_EMAIL_ENABLED "email_enabled"
#define KEY_EMAIL_REQUIRED "email_required"
#define KEY_SYNC_LOG "sync_log"
#define KEY_COOKIE_TIMEOUT "cookie_timeout"
#define KEY_ACCOUNTS_PER_EMAIL "accounts_per_email"
#define KEY_EMAIL_SEARCH_LEVEL "email_search_level"
#define KEY_DEFAULT_STYLE "default_style"
#define KEY_OUNREGISTER_INACTIVE "ounregister_inactive"
#define KEY_OUNREGISTER_FLAGS "ounregister_flags"

#define KEY_ID "id"
#define KEY_PASSWD "passwd"
#define KEY_NICKS "nicks"
#define KEY_NICKS_EX "nicks_ex"
#define KEY_MASKS "masks"
#define KEY_SSLFPS "sslfps"
#define KEY_IGNORES "ignores"
#define KEY_OPSERV_LEVEL "opserv_level"
#define KEY_FLAGS "flags"
#define KEY_REGISTER_ON "register"
#define KEY_LAST_SEEN "lastseen"
#define KEY_INFO "info"
#define KEY_USERLIST_STYLE "user_style"
#define KEY_SCREEN_WIDTH "screen_width"
#define KEY_LAST_AUTHED_HOST "last_authed_host"
#define KEY_LAST_QUIT_HOST "last_quit_host"
#define KEY_EMAIL_ADDR "email_addr"
#define KEY_COOKIE "cookie"
#define KEY_COOKIE_DATA "data"
#define KEY_COOKIE_TYPE "type"
#define KEY_COOKIE_EXPIRES "expires"
#define KEY_ACTIVATION "activation"
#define KEY_PASSWORD_CHANGE "password change"
#define KEY_EMAIL_CHANGE "email change"
#define KEY_ALLOWAUTH "allowauth"
#define KEY_EPITHET "epithet"
#define KEY_TABLE_WIDTH "table_width"
#define KEY_ANNOUNCEMENTS "announcements"
#define KEY_MAXLOGINS "maxlogins"
#define KEY_FAKEHOST "fakehost"
#define KEY_NOTE_NOTE "note"
#define KEY_NOTE_SETTER "setter"
#define KEY_NOTE_DATE "date"
#define KEY_KARMA "karma"
#define KEY_FORCE_HANDLES_LOWERCASE "force_handles_lowercase"

#define KEY_LDAP_ENABLE "ldap_enable"

#ifdef WITH_LDAP
#define KEY_LDAP_URI "ldap_uri"
#define KEY_LDAP_BASE "ldap_base"
#define KEY_LDAP_DN_FMT "ldap_dn_fmt"
#define KEY_LDAP_VERSION "ldap_version"
#define KEY_LDAP_AUTOCREATE "ldap_autocreate"
#define KEY_LDAP_ADMIN_DN "ldap_admin_dn"
#define KEY_LDAP_ADMIN_PASS "ldap_admin_pass"
#define KEY_LDAP_FIELD_ACCOUNT "ldap_field_account"
#define KEY_LDAP_FIELD_PASSWORD "ldap_field_password"
#define KEY_LDAP_FIELD_EMAIL "ldap_field_email"
#define KEY_LDAP_FIELD_OSLEVEL "ldap_field_oslevel"
#define KEY_LDAP_OBJECT_CLASSES "ldap_object_classes"
#define KEY_LDAP_OPER_GROUP_DN "ldap_oper_group_dn"
#define KEY_LDAP_OPER_GROUP_LEVEL "ldap_oper_group_level"
#define KEY_LDAP_FIELD_GROUP_MEMBER "ldap_field_group_member"
#define KEY_LDAP_TIMEOUT "ldap_timeout"
#endif

#define NICKSERV_VALID_CHARS	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

#define NICKSERV_FUNC(NAME) MODCMD_FUNC(NAME)
#define OPTION_FUNC(NAME) int NAME(UNUSED_ARG(struct svccmd *cmd), struct userNode *user, struct handle_info *hi, UNUSED_ARG(unsigned int override), int noreply, unsigned int argc, char *argv[])
typedef OPTION_FUNC(option_func_t);

DEFINE_LIST(handle_info_list, struct handle_info*)

#define NICKSERV_MIN_PARMS(N) do { \
  if (argc < N) { \
    reply("MSG_MISSING_PARAMS", argv[0]); \
    svccmd_send_help_brief(user, nickserv, cmd); \
    return 0; \
  } } while (0)

struct userNode *nickserv;
struct userList curr_helpers;
const char *handle_flags = HANDLE_FLAGS;

extern struct string_list *autojoin_channels;
static struct module *nickserv_module;
static struct service *nickserv_service;
static struct log_type *NS_LOG;
dict_t nickserv_handle_dict; /* contains struct handle_info* */
static dict_t nickserv_id_dict; /* contains struct handle_info* */
static dict_t nickserv_nick_dict; /* contains struct nick_info* */
static dict_t nickserv_opt_dict; /* contains option_func_t* */
static dict_t nickserv_allow_auth_dict; /* contains struct handle_info* */
static dict_t nickserv_email_dict; /* contains struct handle_info_list*, indexed by email addr */
static char handle_inverse_flags[256];
static unsigned int flag_access_levels[32];
static const struct message_entry msgtab[] = {
    { "NSMSG_NO_ANGLEBRACKETS", "The < and > in help indicate that that word is a required parameter, but DO NOT actually type them in messages to me." },
    { "NSMSG_HANDLE_EXISTS", "Account $b%s$b is already registered." },
    { "NSMSG_HANDLE_TOLONG", "The account name %s is too long. Account names must be %lu characters or less."},
    { "NSMSG_PASSWORD_SHORT", "Your password must be at least %lu characters long." },
    { "NSMSG_PASSWORD_ACCOUNT", "Your password may not be the same as your account name." },
    { "NSMSG_PASSWORD_DICTIONARY", "Your password is too simple. You must choose a password that is not just a word or name." },
    { "NSMSG_PASSWORD_READABLE", "Your password must have at least %lu digit(s), %lu capital letter(s), and %lu lower-case letter(s)." },
    { "NSMSG_LDAP_FAIL", "There was a problem in contacting the account server (ldap): %s. Please try again later." },
    { "NSMSG_LDAP_FAIL_ADD", "There was a problem in adding account %s to ldap: %s." },
    { "NSMSG_LDAP_FAIL_SEND_EMAIL", "There was a problem in storing your email address in the account server (ldap): %s. Please try again later." },
    { "NSMSG_LDAP_FAIL_GET_EMAIL", "There was a problem in retrieving your email address from the account server (ldap): %s. Please try again later." },
    { "NSMSG_PARTIAL_REGISTER", "Account has been registered to you; nick was already registered to someone else." },
    { "NSMSG_OREGISTER_VICTIM", "%s has registered a new account for you (named %s)." },
    { "NSMSG_OREGISTER_H_SUCCESS", "Account has been registered." },
    { "NSMSG_REGISTER_H_SUCCESS", "Account has been registered to you." },
    { "NSMSG_REGISTER_HN_SUCCESS", "Account and nick have been registered to you." },
    { "NSMSG_REQUIRE_OPER", "You must be an $bIRC Operator$b to register the first account." },
    { "NSMSG_ROOT_HANDLE", "Account %s has been granted $broot-level privileges$b." },
    { "NSMSG_USE_COOKIE_REGISTER", "To activate your account, you must check your email for the \"cookie\" that has been mailed to it.  When you have it, use the $bcookie$b command to complete registration." },
    { "NSMSG_USE_COOKIE_RESETPASS", "A cookie has been mailed to your account's email address.  You must check your email and use the $bcookie$b command to confirm the password change." },
    { "NSMSG_USE_COOKIE_EMAIL_1", "A cookie has been mailed to the new address you requested.  To finish setting your email address, please check your email for the cookie and use the $bcookie$b command to verify." },
    { "NSMSG_USE_COOKIE_EMAIL_2", "A cookie has been generated, and half mailed to each your old and new addresses.  To finish changing your email address, please check your email for the cookie and use the $bcookie$b command to verify." },
    { "NSMSG_USE_COOKIE_AUTH", "A cookie has been generated and sent to your email address.  Once you have checked your email and received the cookie, auth using the $bcookie$b command." },
    { "NSMSG_COOKIE_LIVE", "Account $b%s$b already has a cookie active.  Please either finish using that cookie, wait for it to expire, or auth to the account and use the $bdelcookie$b command." },
    { "NSMSG_EMAIL_UNACTIVATED", "That email address already has an unused cookie outstanding.  Please use the cookie or wait for it to expire." },
    { "NSMSG_NO_COOKIE", "Your account does not have any cookie issued right now." },
    { "NSMSG_NO_COOKIE_FOREIGN", "The account $b%s$b does not have any cookie issued right now." },
    { "NSMSG_CANNOT_COOKIE", "You cannot use that kind of cookie when you are logged in." },
    { "NSMSG_BAD_COOKIE", "That cookie is not the right one.  Please make sure you are copying it EXACTLY from the email; it is case-sensitive, so $bABC$b is different from $babc$b." },
    { "NSMSG_HANDLE_ACTIVATED", "Your account is now activated (with the password you entered when you registered).  You are now authenticated to your account." },
    { "NSMSG_PASSWORD_CHANGED", "You have successfully changed your password to what you requested with the $bresetpass$b command." },
    { "NSMSG_EMAIL_PROHIBITED", "%s may not be used as an email address: %s" },
    { "NSMSG_EMAIL_OVERUSED", "That email address already has an account. Use RESETPASS if you forgot your password." },
    { "NSMSG_EMAIL_SAME", "That is the email address already there; no need to change it." },
    { "NSMSG_EMAIL_CHANGED", "You have successfully changed your email address." },
    { "NSMSG_BAD_COOKIE_TYPE", "Your account had bad cookie type %d; sorry.  I am confused.  Please report this bug." },
    { "NSMSG_MUST_TIME_OUT", "You must wait for cookies of that type to time out." },
    { "NSMSG_ATE_COOKIE", "I ate the cookie for your account.  You may now have another." },
    { "NSMSG_ATE_FOREIGN_COOKIE", "I ate the cookie for account $b%s$b.  It may now have another." },
    { "NSMSG_USE_RENAME", "You are already authenticated to account $b%s$b -- contact the support staff to rename your account." },
    { "NSMSG_ALREADY_REGISTERING", "You have already used $bREGISTER$b once this session; you may not use it again." },
    { "NSMSG_REGISTER_BAD_NICKMASK", "You must provide a hostmask, or online nick to generate one automatically. (or set a default hostmask in the config such as *@*)." },
    { "NSMSG_NICK_NOT_REGISTERED", "Nick $b%s$b has not been registered to any account." },
    { "NSMSG_HANDLE_NOT_FOUND", "Could not find your account -- did you register yet?" },
    { "NSMSG_ALREADY_AUTHED", "You are already authed to account $b%s$b; you must reconnect to auth to a different account." },
    { "NSMSG_USE_AUTHCOOKIE", "Your hostmask is not valid for account $b%1$s$b.  Please use the $bauthcookie$b command to grant yourself access.  (/msg $N authcookie %1$s)" },
    { "NSMSG_HOSTMASK_INVALID", "Your hostmask is not valid for account $b%s$b." },
    { "NSMSG_USER_IS_SERVICE", "$b%s$b is a network service; you can only use that command on real users." },
    { "NSMSG_USER_PREV_AUTH", "$b%s$b is already authenticated." },
    { "NSMSG_USER_PREV_STAMP", "$b%s$b has authenticated to an account once and cannot authenticate again." },
    { "NSMSG_BAD_MAX_LOGINS", "MaxLogins must be at most %d." },
    { "NSMSG_BAD_ADVANCED", "Advanced must be either 1 to enable it or 0 to disable it." },
    { "NSMSG_LANGUAGE_NOT_FOUND", "Language $b%s$b is not supported; $b%s$b was the closest available match." },
    { "NSMSG_MAX_LOGINS", "Your account already has its limit of %d user(s) logged in." },
    { "NSMSG_STAMPED_REGISTER", "You have already authenticated to an account once this session; you may not register a new account." },
    { "NSMSG_STAMPED_AUTH", "You have already authenticated to an account once this session; you may not authenticate to another." },
    { "NSMSG_STAMPED_RESETPASS", "You have already authenticated to an account once this session; you may not reset your password to authenticate again." },
    { "NSMSG_STAMPED_AUTHCOOKIE",  "You have already authenticated to an account once this session; you may not use a cookie to authenticate to another account." },
    { "NSMSG_TITLE_INVALID", "Titles may contain only a-z, A-Z, 0-9, and '-'.  Please choose another." },
    { "NSMSG_TITLE_TRUNCATED", "That title combined with the user's account name would result in a truncated host; please choose a shorter title." },
    { "NSMSG_FAKEHOST_INVALID", "Fake hosts must be shorter than %d characters and cannot start with a dot." },
    { "NSMSG_HANDLEINFO_ON", "$bAccount Information for %s$b" },
    { "NSMSG_HANDLEINFO_END", "----------End of Account Info-----------" },
    { "NSMSG_HANDLEINFO_ID", "Account ID: %lu" },
    { "NSMSG_HANDLEINFO_REGGED", "Registered on: %s" },
    { "NSMSG_HANDLEINFO_LASTSEEN", "Last seen: %s" },
    { "NSMSG_HANDLEINFO_LASTSEEN_NOW", "Last seen: Right now!" },
    { "NSMSG_HANDLEINFO_KARMA", "Karma: %d" },
    { "NSMSG_HANDLEINFO_VACATION", "On vacation." },
    { "NSMSG_HANDLEINFO_EMAIL_ADDR", "Email address: %s" },
    { "NSMSG_HANDLEINFO_COOKIE_ACTIVATION", "Cookie: There is currently an activation cookie issued for this account" },
    { "NSMSG_HANDLEINFO_COOKIE_PASSWORD", "Cookie: There is currently a password change cookie issued for this account" },
    { "NSMSG_HANDLEINFO_COOKIE_EMAIL", "Cookie: There is currently an email change cookie issued for this account" },
    { "NSMSG_HANDLEINFO_COOKIE_ALLOWAUTH", "Cookie: There is currently an allowauth cookie issued for this account" },
    { "NSMSG_HANDLEINFO_COOKIE_UNKNOWN", "Cookie: There is currently an unknown cookie issued for this account" },
    { "NSMSG_HANDLEINFO_COOKIE_EMAIL_DATA", "Cookie: New email address: %s" },
    { "NSMSG_HANDLEINFO_INFOLINE", "Infoline: %s" },
    { "NSMSG_HANDLEINFO_FLAGS", "Flags: %s" },
    { "NSMSG_HANDLEINFO_OPSERV_LEVEL", "Opserv level: %d " },
    { "NSMSG_HANDLEINFO_EPITHET", "Epithet: %s" },
    { "NSMSG_HANDLEINFO_NOTE", "Note (by %s on %s): %s " },
    { "NSMSG_HANDLEINFO_FAKEHOST", "Fake host: %s" },
    { "NSMSG_INVALID_KARMA", "$b%s$b is not a valid karma modifier." },
    { "NSMSG_SET_KARMA", "$bKARMA:       $b%d$b" },
    { "NSMSG_HANDLEINFO_LAST_HOST", "Last quit hostmask: %s" },
    { "NSMSG_HANDLEINFO_LAST_HOST_UNKNOWN", "Last quit hostmask: Unknown" },
    { "NSMSG_HANDLEINFO_NICKS", "Nickname(s): %s" },
    { "NSMSG_HANDLEINFO_MASKS", "Hostmask(s): %s" },
    { "NSMSG_HANDLEINFO_SSLFPS", "Client Certificate Fingerprints(s): %s" },
    { "NSMSG_HANDLEINFO_IGNORES", "Ignore(s): %s" },
    { "NSMSG_HANDLEINFO_CHANNELS", "Channel(s): %s" },
    { "NSMSG_HANDLEINFO_CURRENT", "Current nickname(s): %s" },
    { "NSMSG_HANDLEINFO_DNR", "Do-not-register (by %s): %s" },
    { "NSMSG_USERINFO_AUTHED_AS", "$b%s$b is authenticated to account $b%s$b." },
    { "NSMSG_USERINFO_NOT_AUTHED", "$b%s$b is not authenticated to any account." },
    { "NSMSG_NICKINFO_ON", "$bNick Information for %s$b" },
    { "NSMSG_NICKINFO_END", "----------End of Nick Info-----------" },
    { "NSMSG_NICKINFO_REGGED", "Registered on: %s" },
    { "NSMSG_NICKINFO_LASTSEEN", "Last seen: %s" },
    { "NSMSG_NICKINFO_LASTSEEN_NOW", "Last seen: Right now!" },
    { "NSMSG_NICKINFO_OWNER", "Account: %s." },
    { "NSMSG_PASSWORD_INVALID", "Incorrect password; please try again." },
    { "NSMSG_PLEASE_SET_EMAIL", "We now require email addresses for users.  Please use the $bset email$b command to set your email address!" },
    { "NSMSG_WEAK_PASSWORD", "WARNING: You are using a password that is considered weak (easy to guess).  It is STRONGLY recommended you change it (now, if not sooner) by typing \"/msg $S@$s PASS oldpass newpass\" (with your current password and a new password)." },
    { "NSMSG_HANDLE_SUSPENDED", "Your $b$N$b account has been suspended; you may not use it." },
    { "NSMSG_AUTH_SUCCESS", "I recognize you." },
    { "NSMSG_ALLOWAUTH_STAFF", "$b%s$b is a helper or oper; please use $bstaff$b after the account name to allowauth." },
    { "NSMSG_AUTH_ALLOWED", "User $b%s$b may now authenticate to account $b%s$b." },
    { "NSMSG_AUTH_ALLOWED_MSG", "You may now authenticate to account $b%s$b by typing $b/msg $N@$s auth %s password$b (using your password).  If you will be using this computer regularly, please type $b/msg $N addmask$b (AFTER you auth) to permanently add your hostmask." },
    { "NSMSG_AUTH_ALLOWED_EMAIL", "You may also (after you auth) type $b/msg $N set email user@your.isp$b to set an email address.  This will let you use the $bauthcookie$b command to be authenticated in the future." },
    { "NSMSG_AUTH_NORMAL_ONLY", "User $b%s$b may now only authenticate to accounts with matching hostmasks." },
    { "NSMSG_AUTH_UNSPECIAL", "User $b%s$b did not have any special auth allowance." },
    { "NSMSG_MUST_AUTH", "You must be authenticated first." },
    { "NSMSG_TOO_MANY_NICKS", "You have already registered the maximum permitted number of nicks." },
    { "NSMSG_NICK_EXISTS", "Nick $b%s$b already registered." },
    { "NSMSG_REGNICK_SUCCESS", "Nick $b%s$b has been registered to you." },
    { "NSMSG_OREGNICK_SUCCESS", "Nick $b%s$b has been registered to account $b%s$b." },
    { "NSMSG_PASS_SUCCESS", "Password changed." },
    { "NSMSG_MASK_INVALID", "$b%s$b is an invalid hostmask." },
    { "NSMSG_ADDMASK_ALREADY", "$b%s$b is already a hostmask in your account." },
    { "NSMSG_ADDMASK_SUCCESS", "Hostmask %s added." },
    { "NSMSG_ADDIGNORE_ALREADY", "$b%s$b is already an ignored hostmask in your account." },
    { "NSMSG_ADDIGNORE_SUCCESS", "Hostmask %s added." },
    { "NSMSG_ADDSSLFP_ALREADY", "$b%s$b is already a client certificate fingerprint in your account." },
    { "NSMSG_ADDSSLFP_SUCCESS", "Client certificate fingerprint %s added." },
    { "NSMSG_DELMASK_NOTLAST", "You may not delete your last hostmask." },
    { "NSMSG_DELMASK_SUCCESS", "Hostmask %s deleted." },
    { "NSMSG_DELMASK_NOT_FOUND", "Unable to find mask to be deleted." },
    { "NSMSG_DELSSLFP_SUCCESS", "Client certificate fingerprint %s deleted." },
    { "NSMSG_DELSSLFP_NOT_FOUND", "Unable to find client certificate fingerprint to be deleted." },
    { "NSMSG_OPSERV_LEVEL_BAD", "You may not promote another oper above your level." },
    { "NSMSG_USE_CMD_PASS", "Please use the PASS command to change your password." },
    { "NSMSG_UNKNOWN_NICK", "I know nothing about nick $b%s$b." },
    { "NSMSG_NOT_YOUR_NICK", "The nick $b%s$b is not registered to you." },
    { "NSMSG_NICK_USER_YOU", "I will not let you kill yourself." },
    { "NSMSG_UNREGNICK_SUCCESS", "Nick $b%s$b has been unregistered." },
    { "NSMSG_UNREGISTER_SUCCESS", "Account $b%s$b has been unregistered." },
    { "NSMSG_UNREGISTER_NICKS_SUCCESS", "Account $b%s$b and all its nicks have been unregistered." },
    { "NSMSG_UNREGISTER_MUST_FORCE", "Account $b%s$b is not inactive or has special flags set; use FORCE to unregister it." },
    { "NSMSG_UNREGISTER_CANNOT_FORCE", "Account $b%s$b is not inactive or has special flags set; have an IRCOp use FORCE to unregister it." },
    { "NSMSG_UNREGISTER_NODELETE", "Account $b%s$b is protected from unregistration." },
    { "NSMSG_HANDLE_STATS", "There are %d nicks registered to your account." },
    { "NSMSG_HANDLE_NONE", "You are not authenticated against any account." },
    { "NSMSG_GLOBAL_STATS", "There are %d accounts and %d nicks registered globally." },
    { "NSMSG_GLOBAL_STATS_NONICK", "There are %d accounts registered." },
    { "NSMSG_CANNOT_GHOST_SELF", "You may not ghost-kill yourself." },
    { "NSMSG_CANNOT_GHOST_USER", "$b%s$b is not authed to your account; you may not ghost-kill them." },
    { "NSMSG_GHOST_KILLED", "$b%s$b has been killed as a ghost." },
    { "NSMSG_ON_VACATION", "You are now on vacation.  Your account will be preserved until you authenticate again." },
    { "NSMSG_NO_ACCESS", "Access denied." },
    { "NSMSG_INVALID_FLAG", "$b%c$b is not a valid $N account flag." },
    { "NSMSG_SET_FLAG", "Applied flags $b%s$b to %s's $N account." },
    { "NSMSG_FLAG_PRIVILEGED", "You have insufficient access to set flag %c." },
    { "NSMSG_DB_UNREADABLE", "Unable to read database file %s; check the log for more information." },
    { "NSMSG_DB_MERGED", "$N merged DB from %s (in "FMT_TIME_T".%03lu seconds)." },
    { "NSMSG_HANDLE_CHANGED", "$b%s$b's account name has been changed to $b%s$b." },
    { "NSMSG_BAD_HANDLE", "Account $b%s$b is not allowed because it is reserved, is too long, or contains invalid characters." },
    { "NSMSG_BAD_NICK", "Nickname $b%s$b not registered because it is in use by a network service, is too long, or contains invalid characters." },
    { "NSMSG_BAD_EMAIL_ADDR", "Please use a well-formed email address." },
    { "NSMSG_FAIL_RENAME", "Account $b%s$b not renamed to $b%s$b because it is in use by a network services, or contains invalid characters." },
    { "NSMSG_ACCOUNT_SEARCH_RESULTS", "The following accounts were found:" },
    { "NSMSG_SEARCH_MATCH", "Match: %s" },
    { "NSMSG_INVALID_ACTION", "%s is an invalid search action." },
    { "NSMSG_CANNOT_MERGE_SELF", "You cannot merge account $b%s$b with itself." },
    { "NSMSG_HANDLES_MERGED", "Merged account $b%s$b into $b%s$b." },
    { "NSMSG_RECLAIM_WARN", "%s is a registered nick - you must auth to account %s or change your nick." },
    { "NSMSG_RECLAIM_HOWTO", "To auth to account %s you must use /msg %s@%s AUTH %s <password>" },
    { "NSMSG_RECLAIM_KILL", "Unauthenticated user of nick." },
    { "NSMSG_RECLAIMED_NONE", "You cannot manually reclaim a nick." },
    { "NSMSG_RECLAIMED_WARN", "Sent a request for %s to change their nick." },
    { "NSMSG_RECLAIMED_SVSNICK", "Forcibly changed %s's nick." },
    { "NSMSG_RECLAIMED_KILL",  "Disconnected %s from the network." },
    { "NSMSG_CLONE_AUTH", "Warning: %s (%s@%s) authed to your account." },
    { "NSMSG_SETTING_LIST", "$b$N account settings$b" },
    { "NSMSG_SETTING_LIST_HEADER", "----------------------------------------" },
    { "NSMSG_SETTING_LIST_END",    "-------------End Of Settings------------" },
    { "NSMSG_INVALID_OPTION", "$b%s$b is an invalid account setting." },
    { "NSMSG_INVALID_ANNOUNCE", "$b%s$b is an invalid announcements value." },
    { "NSMSG_SET_INFO", "$bINFO:         $b%s" },
    { "NSMSG_SET_WIDTH", "$bWIDTH:        $b%d" },
    { "NSMSG_SET_TABLEWIDTH", "$bTABLEWIDTH:   $b%d" },
    { "NSMSG_SET_COLOR", "$bCOLOR:        $b%s" },
    { "NSMSG_SET_PRIVMSG", "$bPRIVMSG:      $b%s" },
    { "NSMSG_SET_STYLE", "$bSTYLE:        $b%s" },
    { "NSMSG_SET_ANNOUNCEMENTS", "$bANNOUNCEMENTS: $b%s" },
    { "NSMSG_SET_AUTOHIDE", "$bAUTOHIDE:     $b%s" },
    { "NSMSG_SET_PASSWORD", "$bPASSWORD:     $b%s" },
    { "NSMSG_SET_FLAGS", "$bFLAGS:        $b%s" },
    { "NSMSG_SET_EMAIL", "$bEMAIL:        $b%s" },
    { "NSMSG_SET_MAXLOGINS", "$bMAXLOGINS:    $b%d" },
    { "NSMSG_SET_ADVANCED", "$bADVANCED:     $b%s" },
    { "NSMSG_SET_LANGUAGE", "$bLANGUAGE:     $b%s" },
    { "NSMSG_SET_LEVEL", "$bLEVEL:        $b%d" },
    { "NSMSG_SET_EPITHET", "$bEPITHET:      $b%s" },
    { "NSMSG_SET_NOTE", "$bNOTE:         $b%s"},
    { "NSMSG_SET_TITLE", "$bTITLE:        $b%s" },
    { "NSMSG_SET_FAKEHOST", "$bFAKEHOST:     $b%s" },

    { "NSMSG_AUTO_OPER", "You have been auto-opered" },
    { "NSMSG_AUTO_OPER_ADMIN", "You have been auto-admined" },

    { "NSEMAIL_ACTIVATION_SUBJECT", "Account verification for %s" },
    { "NSEMAIL_ACTIVATION_BODY", 
        "This email has been sent to verify that this email address belongs to the person who tried to register an account on %1$s.  Your cookie is:\n"
        "%2$s\n"
        "To verify your email address and complete the account registration, log on to %1$s and type the following command:\n"
        "/msg %3$s@%4$s COOKIE %5$s %2$s\n"
        "This command is only used once to complete your account registration, and never again. Once you have run this command, you will need to authenticate everytime you reconnect to the network. To do this, you will have to type this command every time you reconnect:\n"
        "/msg %3$s@%4$s AUTH %5$s your-password\n"
        "(Please remember to fill in 'your-password' with the actual password you gave to us when you registered.)\n"
        "OR configure Login-On-Connect (see http://www.afternet.org/login-on-connect for instructions) to connect pre-logged in every time.\n"
        "\n"
        "If you did NOT request this account, you do not need to do anything.\n"
        "Please contact the %1$s staff if you have questions, and be sure to check our website." },
    { "NSEMAIL_ACTIVATION_BODY_WEB", 
        "This email has been sent to verify that this email address belongs to the person who tried to register an account on %1$s.  Your cookie is:\n"
        "%2$s\n"
        "To verify your email address and complete the account registration, visit the following URL:\n"
        "http://www.afternet.org/index.php?option=com_registration&task=activate&username=%5$s&cookie=%2$s\n"
        "\n"
        "If you did NOT request this account, you do not need to do anything.\n"
        "Please contact the %1$s staff if you have questions, and be sure to check our website." },
    { "NSEMAIL_PASSWORD_CHANGE_SUBJECT", "Password change verification on %s" },
    { "NSEMAIL_PASSWORD_CHANGE_BODY", 
        "This email has been sent to verify that you wish to change the password on your account %5$s.  Your cookie is %2$s.\n"
        "To complete the password change, log on to %1$s and type the following command:\n"
        "/msg %3$s@%4$s COOKIE %5$s %2$s\n"
        "If you did NOT request your password to be changed, you do not need to do anything.\n"
        "Please contact the %1$s staff if you have questions." },
    { "NSEMAIL_PASSWORD_CHANGE_BODY_WEB", 
        "This email has been sent to verify that you wish to change the password on your account %5$s.  Your cookie is %2$s.\n"
        "To complete the password change, click the following URL:\n"
        "http://www.afternet.org/index.php?option=com_registration&task=passcookie&username=%5$s&cookie=%2$s\n"
        "If you did NOT request your password to be changed, you do not need to do anything.\n"
        "Please contact the %1$s staff if you have questions." },
    { "NSEMAIL_EMAIL_CHANGE_SUBJECT", "Email address change verification for %s" },
#ifdef stupid_verify_old_email        
    { "NSEMAIL_EMAIL_CHANGE_BODY_NEW", "This email has been sent to verify that your email address belongs to the same person as account %5$s on %1$s.  The SECOND HALF of your cookie is %2$.*6$s.\nTo verify your address as associated with this account, log on to %1$s and type the following command:\n    /msg %3$s@%4$s COOKIE %5$s ?????%2$.*6$s\n(Replace the ????? with the FIRST HALF of the cookie, as sent to your OLD email address.)\nIf you did NOT request this email address to be associated with this account, you do not need to do anything.  Please contact the %1$s staff if you have questions." },
    { "NSEMAIL_EMAIL_CHANGE_BODY_OLD", "This email has been sent to verify that you want to change your email for account %5$s on %1$s from this address to %7$s.  The FIRST HALF of your cookie is %2$.*6$s\nTo verify your new address as associated with this account, log on to %1$s and type the following command:\n    /msg %3$s@%4$s COOKIE %5$s %2$.*6$s?????\n(Replace the ????? with the SECOND HALF of the cookie, as sent to your NEW email address.)\nIf you did NOT request this change of email address, you do not need to do anything.  Please contact the %1$s staff if you have questions." },
#endif
    { "NSEMAIL_EMAIL_VERIFY_SUBJECT", "Email address verification for %s" },
    { "NSEMAIL_EMAIL_VERIFY_BODY", "This email has been sent to verify that this address belongs to the same person as %5$s on %1$s.  Your cookie is %2$s.\nTo verify your address as associated with this account, log on to %1$s and type the following command:\n    /msg %3$s@%4$s COOKIE %5$s %2$s\nIf you did NOT request this email address to be associated with this account, you do not need to do anything.  Please contact the %1$s staff if you have questions." },
    { "NSEMAIL_ALLOWAUTH_SUBJECT", "Authentication allowed for %s" },
    { "NSEMAIL_ALLOWAUTH_BODY", "This email has been sent to let you authenticate (auth) to account %5$s on %1$s.  Your cookie is %2$s.\nTo auth to that account, log on to %1$s and type the following command:\n    /msg %3$s@%4$s COOKIE %5$s %2$s\nIf you did NOT request this authorization, you do not need to do anything.  Please contact the %1$s staff if you have questions." },
    { "NSMSG_NOT_VALID_FAKEHOST_DOT", "$b%s$b is not a valid vhost. (needs at least one dot)" },
    { "NSMSG_NOT_VALID_FAKEHOST_AT", "$b%s$b is not a valid vhost. (it can not have a '@')" },
    { "NSMSG_DENIED_FAKEHOST_WORD", "Access denied because there's a prohibited word in $b%s$b (%s)." },
    { "NSMSG_NOT_VALID_FAKEHOST_LEN", "$b%s$b is not a valid vhost. (can only be 63 characters)" },
    { "NSMSG_NOT_VALID_FAKEHOST_TLD_LEN", "$b%s$b is not a valid vhost. (TLD can only be 4 characters and less)" },
    { "NSMSG_NOT_VALID_FAKEHOST_REGEX", "$b%s$b is not allowed by the admin, consult the valid vhost regex pattern in the config file under nickserv/valid_fakehost_regex." },
    { "CHECKPASS_YES", "Yes." },
    { "CHECKPASS_NO", "No." },
    { "CHECKEMAIL_NOT_SET", "No email set." },
    { "CHECKEMAIL_YES", "Yes." },
    { "CHECKEMAIL_NO", "No." },
    { "NSMSG_DEFCON_NO_NEW_NICKS", "You cannot register new %s at this time, please try again soon" },
    { NULL, NULL }
};

static void nickserv_reclaim(struct userNode *user, struct nick_info *ni, enum reclaim_action action);
static void nickserv_reclaim_p(void *data);
static int nickserv_addmask(struct userNode *user, struct handle_info *hi, const char *mask);

struct nickserv_config nickserv_conf;

/* We have 2^32 unique account IDs to use. */
unsigned long int highest_id = 0;

static char *
canonicalize_hostmask(char *mask)
{
    char *out = mask, *temp;
    if ((temp = strchr(mask, '!'))) {
	temp++;
	while (*temp) *out++ = *temp++;
	*out++ = 0;
    }
    return mask;
}

static struct handle_note *
nickserv_add_note(const char *setter, time_t date, const char *text)
{
    struct handle_note *note = calloc(1, sizeof(*note) + strlen(text));

    strncpy(note->setter, setter, sizeof(note->setter)-1);
    note->date = date;
    memcpy(note->note, text, strlen(text));
    return note;
}

static struct handle_info *
register_handle(const char *handle, const char *passwd, UNUSED_ARG(unsigned long id))
{
    struct handle_info *hi;

    hi = calloc(1, sizeof(*hi));
    hi->userlist_style = nickserv_conf.default_style ? nickserv_conf.default_style : HI_DEFAULT_STYLE;
    hi->announcements = '?';
    hi->handle = strdup(handle);
    safestrncpy(hi->passwd, passwd, sizeof(hi->passwd));
    hi->infoline = NULL;
    dict_insert(nickserv_handle_dict, hi->handle, hi);

    return hi;
}

static void
register_nick(const char *nick, struct handle_info *owner)
{
    struct nick_info *ni;
    ni = malloc(sizeof(struct nick_info));
    safestrncpy(ni->nick, nick, sizeof(ni->nick));
    ni->registered = now;
    ni->lastseen = now;
    ni->owner = owner;
    ni->next = owner->nicks;
    owner->nicks = ni;
    dict_insert(nickserv_nick_dict, ni->nick, ni);
}

static void
delete_nick(struct nick_info *ni)
{
    struct nick_info *last, *next;
    struct userNode *user;
    /* Check to see if we should mark a user as unregistered. */
    if ((user = GetUserH(ni->nick)) && IsReggedNick(user)) {
        user->modes &= ~FLAGS_REGNICK;
        irc_regnick(user);
    }
    /* Remove ni from the nick_info linked list. */
    if (ni == ni->owner->nicks) {
	ni->owner->nicks = ni->next;
    } else {
	last = ni->owner->nicks;
	next = last->next;
	while (next != ni) {
	    last = next;
	    next = last->next;
	}
	last->next = next->next;
    }
    dict_remove(nickserv_nick_dict, ni->nick);
}

static unreg_func_t *unreg_func_list;
static void **unreg_func_list_extra;
static unsigned int unreg_func_size = 0, unreg_func_used = 0;

void
reg_unreg_func(unreg_func_t func, void *extra)
{
    if (unreg_func_used == unreg_func_size) {
	if (unreg_func_size) {
	    unreg_func_size <<= 1;
	    unreg_func_list = realloc(unreg_func_list, unreg_func_size*sizeof(unreg_func_t));
        unreg_func_list_extra = realloc(unreg_func_list_extra, unreg_func_size*sizeof(void*));
	} else {
	    unreg_func_size = 8;
	    unreg_func_list = malloc(unreg_func_size*sizeof(unreg_func_t));
        unreg_func_list_extra = malloc(unreg_func_size*sizeof(void*));
	}
    }
    unreg_func_list[unreg_func_used] = func;
    unreg_func_list_extra[unreg_func_used++] = extra;
}

static void
nickserv_free_cookie(void *data)
{
    struct handle_cookie *cookie = data;
    if (cookie->hi) cookie->hi->cookie = NULL;
    if (cookie->data) free(cookie->data);
    free(cookie);
}

static void
free_handle_info(void *vhi)
{
    struct handle_info *hi = vhi;

    free_string_list(hi->masks);
    free_string_list(hi->sslfps);
    free_string_list(hi->ignores);
    assert(!hi->users);

    while (hi->nicks)
        delete_nick(hi->nicks);
    free(hi->infoline);
    free(hi->epithet);
    free(hi->note);
    free(hi->fakehost);
    if (hi->cookie) {
        timeq_del(hi->cookie->expires, nickserv_free_cookie, hi->cookie, 0);
        nickserv_free_cookie(hi->cookie);
    }
    if (hi->email_addr) {
        struct handle_info_list *hil = dict_find(nickserv_email_dict, hi->email_addr, NULL);
        handle_info_list_remove(hil, hi);
        if (!hil->used)
            dict_remove(nickserv_email_dict, hi->email_addr);
    }
    free(hi);
}

static void set_user_handle_info(struct userNode *user, struct handle_info *hi, int stamp);

static int
nickserv_unregister_handle(struct handle_info *hi, struct userNode *notify, struct userNode *bot)
{
    unsigned int n;
    struct userNode *uNode;

#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
        int rc;
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            if( (rc = ldap_delete_account(hi->handle)) != LDAP_SUCCESS) {
               if(notify) {
                    send_message(notify, bot, "NSMSG_LDAP_FAIL", ldap_err2string(rc));
               }
               if(rc != LDAP_NO_SUCH_OBJECT)
                 return false; /* if theres noone there to delete, its kinda ok, right ?:) */
            }
        }
    }
#endif
    for (n=0; n<unreg_func_used; n++)
        unreg_func_list[n](notify, hi, unreg_func_list_extra[n]);
    while (hi->users) {
        uNode = GetUserH(hi->users->nick);
        if (uNode)
            irc_delete(uNode);
        set_user_handle_info(hi->users, NULL, 0);
    }
    if (notify) {
        if (nickserv_conf.disable_nicks)
            send_message(notify, bot, "NSMSG_UNREGISTER_SUCCESS", hi->handle);
        else
            send_message(notify, bot, "NSMSG_UNREGISTER_NICKS_SUCCESS", hi->handle);
    }

    if (nickserv_conf.sync_log)
        SyncLog("UNREGISTER %s", hi->handle);

    dict_remove(nickserv_handle_dict, hi->handle);
    return true;
}

struct handle_info*
get_handle_info(const char *handle)
{
    return dict_find(nickserv_handle_dict, handle, 0);
}

struct nick_info*
get_nick_info(const char *nick)
{
    return nickserv_conf.disable_nicks ? 0 : dict_find(nickserv_nick_dict, nick, 0);
}

struct modeNode *
find_handle_in_channel(struct chanNode *channel, struct handle_info *handle, struct userNode *except)
{
    unsigned int nn;
    struct modeNode *mn;

    for (nn=0; nn<channel->members.used; ++nn) {
        mn = channel->members.list[nn];
        if ((mn->user != except) && (mn->user->handle_info == handle))
            return mn;
    }
    return NULL;
}

int
oper_has_access(struct userNode *user, struct userNode *bot, unsigned int min_level, unsigned int quiet) {
    if (!user->handle_info) {
        if (!quiet)
            send_message(user, bot, "MSG_AUTHENTICATE");
        return 0;
    }

    if (!IsOper(user) && (!IsHelping(user) || min_level)) {
	if (!quiet)
            send_message(user, bot, "NSMSG_NO_ACCESS");
	return 0;
    }

    if (HANDLE_FLAGGED(user->handle_info, OPER_SUSPENDED)) {
	if (!quiet)
            send_message(user, bot, "MSG_OPER_SUSPENDED");
	return 0;
    }

    if (user->handle_info->opserv_level < min_level) {
	if (!quiet)
            send_message(user, bot, "NSMSG_NO_ACCESS");
	return 0;
    }

    return 1;
}

static int
is_valid_handle(const char *handle)
{
    struct userNode *user;
    /* cant register a juped nick/service nick as handle, to prevent confusion */
    user = GetUserH(handle);
    if (user && IsLocal(user))
        return 0;
    /* check against maximum length */
    if (strlen(handle) > NICKSERV_HANDLE_LEN)
	return 0;
    /* for consistency, only allow account names that could be nicks */
    if (!is_valid_nick(handle))
        return 0;
    /* disallow account names that look like bad words */
    if (opserv_bad_channel(handle))
        return 0;
    /* test either regex or containing all valid chars */
    if (nickserv_conf.valid_handle_regex_set) {
        int err = regexec(&nickserv_conf.valid_handle_regex, handle, 0, 0, 0);
        if (err) {
            char buff[256];
            buff[regerror(err, &nickserv_conf.valid_handle_regex, buff, sizeof(buff))] = 0;
            log_module(NS_LOG, LOG_INFO, "regexec error: %s (%d)", buff, err);
        }
        return !err;
    } else {
        return !handle[strspn(handle, NICKSERV_VALID_CHARS)];
    }
}

static int
is_registerable_nick(const char *nick)
{
    struct userNode *user;
    /* cant register a juped nick/service nick as nick, to prevent confusion */
    user = GetUserH(nick);
    if (user && IsLocal(user))
        return 0;
    /* for consistency, only allow nicks names that could be nicks */
    if (!is_valid_nick(nick))
        return 0;
    /* disallow nicks that look like bad words */
    if (opserv_bad_channel(nick))
        return 0;
    /* check length */
    if (strlen(nick) > NICKLEN)
        return 0;
    /* test either regex or as valid handle */
    if (nickserv_conf.valid_nick_regex_set) {
        int err = regexec(&nickserv_conf.valid_nick_regex, nick, 0, 0, 0);
        if (err) {
            char buff[256];
            buff[regerror(err, &nickserv_conf.valid_nick_regex, buff, sizeof(buff))] = 0;
            log_module(NS_LOG, LOG_INFO, "regexec error: %s (%d)", buff, err);
        }
        return !err;
    }
    return 1;
}
/*  this has been replaced with one in tools.c

static int
is_valid_email_addr(const char *email)
{
    return strchr(email, '@') != NULL;
}

*/ 

static const char *
visible_email_addr(struct userNode *user, struct handle_info *hi)
{
    if (hi->email_addr) {
        if (oper_has_access(user, nickserv, nickserv_conf.email_visible_level, 1)) {
            return hi->email_addr;
        } else {
            return "Set.";
        }
    } else {
        return "Not set.";
    }
}

struct handle_info *
smart_get_handle_info(struct userNode *service, struct userNode *user, const char *name)
{
    struct handle_info *hi;
    struct userNode *target;

    switch (*name) {
    case '*':
        if (!(hi = get_handle_info(++name))) {
            send_message(user, service, "MSG_HANDLE_UNKNOWN", name);
            return 0;
        }
        return hi;
    default:
        if (!(target = GetUserH(name))) {
            send_message(user, service, "MSG_NICK_UNKNOWN", name);
            return 0;
        }
        if (IsLocal(target)) {
	    if (IsService(target))
                send_message(user, service, "NSMSG_USER_IS_SERVICE", target->nick);
	    else
                send_message(user, service, "MSG_USER_AUTHENTICATE", target->nick);
            return 0;
        }
        if (!(hi = target->handle_info)) {
            send_message(user, service, "MSG_USER_AUTHENTICATE", target->nick);
            return 0;
        }
        return hi;
    }
}

int
oper_outranks(struct userNode *user, struct handle_info *hi) {
    if (user->handle_info->opserv_level > hi->opserv_level)
        return 1;
    if (user->handle_info->opserv_level == hi->opserv_level) {
        if ((user->handle_info->opserv_level == 1000)
            || (user->handle_info == hi)
            || ((user->handle_info->opserv_level == 0)
                && !(HANDLE_FLAGGED(hi, SUPPORT_HELPER) || HANDLE_FLAGGED(hi, NETWORK_HELPER))
                && HANDLE_FLAGGED(user->handle_info, HELPING))) {
            return 1;
        }
    }
    send_message(user, nickserv, "MSG_USER_OUTRANKED", hi->handle);
    return 0;
}

struct handle_info *
get_victim_oper(struct userNode *user, const char *target)
{
    struct handle_info *hi;
    if (!(hi = smart_get_handle_info(nickserv, user, target)))
        return 0;
    if (HANDLE_FLAGGED(user->handle_info, OPER_SUSPENDED)) {
	send_message(user, nickserv, "MSG_OPER_SUSPENDED");
	return 0;
    }
    return oper_outranks(user, hi) ? hi : NULL;
}

static int
valid_user_for(struct userNode *user, struct handle_info *hi)
{
    unsigned int ii;

    /* If no hostmasks on the account, allow it. */
    if (!hi->masks->used)
        return 1;
    /* If any hostmask matches, allow it. */
    for (ii=0; ii<hi->masks->used; ii++)
        if (user_matches_glob(user, hi->masks->list[ii], 0, 0))
            return 1;
    /* If they are allowauthed to this account, allow it (removing the aa). */
    if (dict_find(nickserv_allow_auth_dict, user->nick, NULL) == hi) {
	dict_remove(nickserv_allow_auth_dict, user->nick);
	return 2;
    }
    /* The user is not allowed to use this account. */
    return 0;
}

static int
valid_user_sslfp(struct userNode *user, struct handle_info *hi)
{
    unsigned int ii;

    if (!hi->sslfps->used)
        return 0;
    if (!(user->sslfp))
        return 0;

    /* If any SSL fingerprint matches, allow it. */
    for (ii=0; ii<hi->sslfps->used; ii++)
        if (!irccasecmp(user->sslfp, hi->sslfps->list[ii]))
            return 1;

    /* No valid SSL fingerprint found. */
    return 0;
}

static int
is_secure_password(const char *handle, const char *pass, struct userNode *user)
{
    unsigned int i, len;
    unsigned int cnt_digits = 0, cnt_upper = 0, cnt_lower = 0;
    int p;

    len = strlen(pass);
    if (len < nickserv_conf.password_min_length) {
        if (user)
            send_message(user, nickserv, "NSMSG_PASSWORD_SHORT", nickserv_conf.password_min_length);
        return 0;
    }
    if (!irccasecmp(pass, handle)) {
        if (user)
            send_message(user, nickserv, "NSMSG_PASSWORD_ACCOUNT");
        return 0;
    }
    dict_find(nickserv_conf.weak_password_dict, pass, &p);
    if (p) {
        if (user)
            send_message(user, nickserv, "NSMSG_PASSWORD_DICTIONARY");
        return 0;
    }
    for (i=0; i<len; i++) {
	if (isdigit(pass[i]))
            cnt_digits++;
	if (isupper(pass[i]))
            cnt_upper++;
	if (islower(pass[i]))
            cnt_lower++;
    }
    if ((cnt_lower < nickserv_conf.password_min_lower)
	|| (cnt_upper < nickserv_conf.password_min_upper)
	|| (cnt_digits < nickserv_conf.password_min_digits)) {
        if (user)
            send_message(user, nickserv, "NSMSG_PASSWORD_READABLE", nickserv_conf.password_min_digits, nickserv_conf.password_min_upper, nickserv_conf.password_min_lower);
        return 0;
    }
    return 1;
}

static auth_func_t *auth_func_list;
static void **auth_func_list_extra;
static unsigned int auth_func_size = 0, auth_func_used = 0;

void
reg_auth_func(auth_func_t func, void *extra)
{
    if (auth_func_used == auth_func_size) {
	if (auth_func_size) {
	    auth_func_size <<= 1;
	    auth_func_list = realloc(auth_func_list, auth_func_size*sizeof(auth_func_t));
        auth_func_list_extra = realloc(auth_func_list_extra, auth_func_size*sizeof(void*));
	} else {
	    auth_func_size = 8;
	    auth_func_list = malloc(auth_func_size*sizeof(auth_func_t));
        auth_func_list_extra = malloc(auth_func_size*sizeof(void*));
	}
    }
    auth_func_list[auth_func_used] = func;
    auth_func_list_extra[auth_func_used++] = extra;
}

static handle_rename_func_t *rf_list;
static void **rf_list_extra;
static unsigned int rf_list_size, rf_list_used;

void
reg_handle_rename_func(handle_rename_func_t func, void *extra)
{
    if (rf_list_used == rf_list_size) {
        if (rf_list_size) {
            rf_list_size <<= 1;
            rf_list = realloc(rf_list, rf_list_size*sizeof(rf_list[0]));
            rf_list_extra = realloc(rf_list_extra, rf_list_size*sizeof(void*));
        } else {
            rf_list_size = 8;
            rf_list = malloc(rf_list_size*sizeof(rf_list[0]));
            rf_list_extra = malloc(rf_list_size*sizeof(void*));
        }
    }
    rf_list[rf_list_used] = func;
    rf_list_extra[rf_list_used++] = extra;
}

static char *
generate_fakehost(struct handle_info *handle)
{
    struct userNode *target;
    extern const char *hidden_host_suffix;
    static char buffer[HOSTLEN+1];
    char *data;
    int style = 1;

    if (!handle->fakehost) {
        data = conf_get_data("server/hidden_host_type", RECDB_QSTRING);
        if (data)
            style = atoi(data);

        if ((style == 1) || (style == 3))
            snprintf(buffer, sizeof(buffer), "%s.%s", handle->handle, hidden_host_suffix);
        else if (style == 2) {
            /* Due to the way fakehost is coded theres no way i can
               get the exact user, so for now ill just take the first
               authed user. */
            for (target = handle->users; target; target = target->next_authed)
               break;

            if (target)
               snprintf(buffer, sizeof(buffer), "%s", target->crypthost);
            else
               strncpy(buffer, "none", sizeof(buffer));
        }
        return buffer;
    } else if (handle->fakehost[0] == '.') {
        /* A leading dot indicates the stored value is actually a title. */
        snprintf(buffer, sizeof(buffer), "%s.%s.%s", handle->handle, handle->fakehost+1, nickserv_conf.titlehost_suffix);
        return buffer;
    }
    return handle->fakehost;
}

static void
apply_fakehost(struct handle_info *handle)
{
    struct userNode *target;
    char *fake;

    if (!handle->users)
        return;
    fake = generate_fakehost(handle);
    for (target = handle->users; target; target = target->next_authed)
        assign_fakehost(target, fake, 1);
}

void send_func_list(struct userNode *user)
{
    unsigned int n;
    struct handle_info *old_info;

    old_info = user->handle_info;

    for (n=0; n<auth_func_used; n++)
        auth_func_list[n](user, old_info, auth_func_list_extra[n]);
}

static void
set_user_handle_info(struct userNode *user, struct handle_info *hi, int stamp)
{
    unsigned int n;
    struct handle_info *old_info;

    /* This can happen if somebody uses COOKIE while authed, or if
     * they re-auth to their current handle (which is silly, but users
     * are like that). */
    if (user->handle_info == hi)
        return;

    if (user->handle_info) {
	struct userNode *other;
        struct nick_info* ni;

	if (IsHelper(user))
            userList_remove(&curr_helpers, user);

	/* remove from next_authed linked list */
	if (user->handle_info->users == user) {
	    user->handle_info->users = user->next_authed;
        } else if (user->handle_info->users != NULL) {
	    for (other = user->handle_info->users;
		 other->next_authed != user;
		 other = other->next_authed) ;
	    other->next_authed = user->next_authed;
        } else {
            /* No users authed to the account - can happen if they get
             * killed for authing. */
	}
        /* if nobody left on old handle, and they're not an oper, remove !god */
        if (!user->handle_info->users && !user->handle_info->opserv_level)
            HANDLE_CLEAR_FLAG(user->handle_info, HELPING);
        /* record them as being last seen at this time */
	user->handle_info->lastseen = now;
        if ((ni = get_nick_info(user->nick)))
            ni->lastseen = now;
        /* and record their hostmask */
        snprintf(user->handle_info->last_quit_host, sizeof(user->handle_info->last_quit_host), "%s@%s", user->ident, user->hostname);
    }
    old_info = user->handle_info;
    user->handle_info = hi;
    if (hi && !hi->users && !hi->opserv_level)
        HANDLE_CLEAR_FLAG(hi, HELPING);

    /* Call auth handlers */
    if (!GetUserH(user->nick))
      user->loc = 1;

    if (hi) {
        struct nick_info *ni;

        HANDLE_CLEAR_FLAG(hi, FROZEN);
        if (nickserv_conf.warn_clone_auth) {
            struct userNode *other;
            for (other = hi->users; other; other = other->next_authed)
                send_message(other, nickserv, "NSMSG_CLONE_AUTH", user->nick, user->ident, user->hostname);
        }

        /* Add this auth to users list of current auths */
	user->next_authed = hi->users;
	hi->users = user;
	hi->lastseen = now;
        /* Add to helpers list */
        if (IsHelper(user) && !userList_contains(&curr_helpers, user))
            userList_append(&curr_helpers, user);

        /* Set the fakehost */
        if (hi->fakehost || old_info)
            apply_fakehost(hi);

        if (stamp) {
#ifdef WITH_PROTOCOL_P10
            /* Stamp users with their account name. */
            char *id = hi->handle;
#else
            const char *id = "???";
#endif
            /* Mark all the nicks registered to this
             * account as registered nicks 
             *  -  Why not just this one? -rubin */
            if (!nickserv_conf.disable_nicks) {
                struct nick_info *ni2;
                for (ni2 = hi->nicks; ni2; ni2 = ni2->next) {
                    if (!irccasecmp(user->nick, ni2->nick)) {
                        user->modes |= FLAGS_REGNICK;
                        break;
                    }
                }
            }
            /* send the account to the ircd */
            StampUser(user, id, hi->registered);
        }

        /* Stop trying to kick this user off their nick */
        if ((ni = get_nick_info(user->nick)) && (ni->owner == hi)) {
            timeq_del(0, nickserv_reclaim_p, user, TIMEQ_IGNORE_WHEN);
            ni->lastseen = now;
        }
    } else {
        /* We cannot clear the user's account ID, unfortunately. */
	user->next_authed = NULL;
    }

    /* Call auth handlers */
    if (GetUserH(user->nick)) {
        for (n=0; n<auth_func_used; n++) {
            auth_func_list[n](user, old_info, auth_func_list_extra[n]);
            if (user->dead)
                return;
        }
    }
}

static struct handle_info*
nickserv_register(struct userNode *user, struct userNode *settee, const char *handle, const char *passwd, int no_auth)
{
    struct handle_info *hi;
    struct nick_info *ni;
    char crypted[MD5_CRYPT_LENGTH] = "";

    if ((hi = dict_find(nickserv_handle_dict, handle, NULL))) {
        if(user)
	  send_message(user, nickserv, "NSMSG_HANDLE_EXISTS", handle);
	return 0;
    }

    if(strlen(handle) > 30)
    {  
        if(user)
          send_message(user, nickserv, "NSMSG_HANDLE_TOLONG", handle, 30);
        return 0;
    }

    if (passwd)
    {
        if (!is_secure_password(handle, passwd, user))
            return 0;

        cryptpass(passwd, crypted);
    }
#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
        int rc;
        rc = ldap_do_add(handle, (no_auth || !passwd ? NULL : crypted), NULL);
        if(LDAP_SUCCESS != rc && LDAP_ALREADY_EXISTS != rc ) {
           if(user)
             send_message(user, nickserv, "NSMSG_LDAP_FAIL", ldap_err2string(rc));
           return 0;
        }
    }
#endif
    hi = register_handle(handle, crypted, 0);
    hi->masks = alloc_string_list(1);
    hi->sslfps = alloc_string_list(1);
    hi->ignores = alloc_string_list(1);
    hi->users = NULL;
    hi->language = lang_C;
    hi->registered = now;
    hi->lastseen = now;
    hi->flags = HI_DEFAULT_FLAGS;
    if (settee && !no_auth)
        set_user_handle_info(settee, hi, 1);

    if (user != settee) {
      if(user)
        send_message(user, nickserv, "NSMSG_OREGISTER_H_SUCCESS");
    }
    else if (nickserv_conf.disable_nicks) {
      if(user) {
        send_message(user, nickserv, "NSMSG_REGISTER_H_SUCCESS");
      }
    }
    else if (user && (ni = dict_find(nickserv_nick_dict, user->nick, NULL))) {
      if(user) {
        send_message(user, nickserv, "NSMSG_PARTIAL_REGISTER");
      }
    }
    else {
        if(user) {
          if (is_registerable_nick(user->nick)) {
            register_nick(user->nick, hi);
            send_message(user, nickserv, "NSMSG_REGISTER_HN_SUCCESS");
          }
        }
        else {
          if (is_registerable_nick(handle)) {
            register_nick(handle, hi);
          }
        }
    }
    if (settee && (user != settee)) {
      if(user) {
        send_message(settee, nickserv, "NSMSG_OREGISTER_VICTIM", user->nick, hi->handle);
      }
    }
    return hi;
}

static void
nickserv_bake_cookie(struct handle_cookie *cookie)
{
    cookie->hi->cookie = cookie;
    timeq_add(cookie->expires, nickserv_free_cookie, cookie);
}

/* Contributed by the great sneep of afternet ;) */
/* Since this gets used in a URL, we want to avoid stuff that confuses
 * email clients such as ] and ?. a-z, 0-9 only.
 */
void genpass(char *str, int len)
{
        int i = 0;
        char c = 0;

        for(i = 0; i < len; i++)
        {
                do
                {
                        c = (char)((float)rand() / (float)RAND_MAX * (float)256);
                } while(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')));
                str[i] = c;
        }
        str[i] = '\0';
        return;
}

static void
nickserv_make_cookie(struct userNode *user, struct handle_info *hi, enum cookie_type type, const char *cookie_data, int weblink)
{
    struct handle_cookie *cookie;
    char subject[128], body[4096], *misc;
    const char *netname, *fmt;
    int first_time = 0;

    if (hi->cookie) {
        send_message(user, nickserv, "NSMSG_COOKIE_LIVE", hi->handle);
        return;
    }

    cookie = calloc(1, sizeof(*cookie));
    cookie->hi = hi;
    cookie->type = type;
    cookie->data = cookie_data ? strdup(cookie_data) : NULL;

    cookie->expires = now + nickserv_conf.cookie_timeout;
    /* Adding dedicated password gen function for more control -Rubin */
    genpass(cookie->cookie, 10);
    /*
     *inttobase64(cookie->cookie, rand(), 5);
     *inttobase64(cookie->cookie+5, rand(), 5);
     */

    netname = nickserv_conf.network_name;
    subject[0] = 0;

    switch (cookie->type) {
    case ACTIVATION:
        hi->passwd[0] = 0; /* invalidate password */
        send_message(user, nickserv, "NSMSG_USE_COOKIE_REGISTER");
        fmt = handle_find_message(hi, "NSEMAIL_ACTIVATION_SUBJECT");
        snprintf(subject, sizeof(subject), fmt, netname);

        if(weblink)
            fmt = handle_find_message(hi, "NSEMAIL_ACTIVATION_BODY_WEB");
        else
            fmt = handle_find_message(hi, "NSEMAIL_ACTIVATION_BODY");

        snprintf(body, sizeof(body), fmt, netname, cookie->cookie, nickserv->nick, self->name, hi->handle);
        first_time = 1;
        break;
    case PASSWORD_CHANGE:
        send_message(user, nickserv, "NSMSG_USE_COOKIE_RESETPASS");
        fmt = handle_find_message(hi, "NSEMAIL_PASSWORD_CHANGE_SUBJECT");
        snprintf(subject, sizeof(subject), fmt, netname);
        if(weblink)
            fmt = handle_find_message(hi, "NSEMAIL_PASSWORD_CHANGE_BODY_WEB");
        else
            fmt = handle_find_message(hi, "NSEMAIL_PASSWORD_CHANGE_BODY");
        snprintf(body, sizeof(body), fmt, netname, cookie->cookie, nickserv->nick, self->name, hi->handle);
        first_time = 0;
        break;
    case EMAIL_CHANGE:
        misc = hi->email_addr;
        hi->email_addr = cookie->data;
#ifdef stupid_verify_old_email        
        if (misc) {
            send_message(user, nickserv, "NSMSG_USE_COOKIE_EMAIL_2");
            fmt = handle_find_message(hi, "NSEMAIL_EMAIL_CHANGE_SUBJECT");
            snprintf(subject, sizeof(subject), fmt, netname);
            fmt = handle_find_message(hi, "NSEMAIL_EMAIL_CHANGE_BODY_NEW");
            snprintf(body, sizeof(body), fmt, netname, cookie->cookie+COOKIELEN/2, nickserv->nick, self->name, hi->handle, COOKIELEN/2);
            mail_send(nickserv, hi, subject, body, 1);
            fmt = handle_find_message(hi, "NSEMAIL_EMAIL_CHANGE_BODY_OLD");
            snprintf(body, sizeof(body), fmt, netname, cookie->cookie, nickserv->nick, self->name, hi->handle, COOKIELEN/2, hi->email_addr);
            first_time = 1;
        } else {
#endif
            send_message(user, nickserv, "NSMSG_USE_COOKIE_EMAIL_1");
            fmt = handle_find_message(hi, "NSEMAIL_EMAIL_VERIFY_SUBJECT");
            snprintf(subject, sizeof(subject), fmt, netname);
            fmt = handle_find_message(hi, "NSEMAIL_EMAIL_VERIFY_BODY");
            snprintf(body, sizeof(body), fmt, netname, cookie->cookie, nickserv->nick, self->name, hi->handle);
            mail_send(nickserv, hi, subject, body, 1);
            subject[0] = 0;
#ifdef stupid_verify_old_email
        }
#endif
        hi->email_addr = misc;
        break;
    case ALLOWAUTH:
        fmt = handle_find_message(hi, "NSEMAIL_ALLOWAUTH_SUBJECT");
        snprintf(subject, sizeof(subject), fmt, netname);
        fmt = handle_find_message(hi, "NSEMAIL_ALLOWAUTH_BODY");
        snprintf(body, sizeof(body), fmt, netname, cookie->cookie, nickserv->nick, self->name, hi->handle);
        send_message(user, nickserv, "NSMSG_USE_COOKIE_AUTH");
        break;
    default:
        log_module(NS_LOG, LOG_ERROR, "Bad cookie type %d in nickserv_make_cookie.", cookie->type);
        break;
    }
    if (subject[0])
        mail_send(nickserv, hi, subject, body, first_time);
    nickserv_bake_cookie(cookie);
}

static void
nickserv_eat_cookie(struct handle_cookie *cookie)
{
    cookie->hi->cookie = NULL;
    timeq_del(cookie->expires, nickserv_free_cookie, cookie, 0);
    nickserv_free_cookie(cookie);
}

static void
nickserv_free_email_addr(void *data)
{
    handle_info_list_clean(data);
    free(data);
}

static void
nickserv_set_email_addr(struct handle_info *hi, const char *new_email_addr)
{
    struct handle_info_list *hil;
    /* Remove from old handle_info_list ... */
    if (hi->email_addr && (hil = dict_find(nickserv_email_dict, hi->email_addr, 0))) {
        handle_info_list_remove(hil, hi);
        if (!hil->used) dict_remove(nickserv_email_dict, hil->tag);
        hi->email_addr = NULL;
    }
    /* Add to the new list.. */
    if (new_email_addr) {
        if (!(hil = dict_find(nickserv_email_dict, new_email_addr, 0))) {
            hil = calloc(1, sizeof(*hil));
            hil->tag = strdup(new_email_addr);
            handle_info_list_init(hil);
            dict_insert(nickserv_email_dict, hil->tag, hil);
        }
        handle_info_list_append(hil, hi);
        hi->email_addr = hil->tag;
    }
}

static NICKSERV_FUNC(cmd_register)
{
    irc_in_addr_t ip;
    struct handle_info *hi;
    const char *email_addr, *password;
    char syncpass[MD5_CRYPT_LENGTH];
    int no_auth, weblink;

    if (checkDefCon(DEFCON_NO_NEW_NICKS) && !IsOper(user)) {
        reply("NSMSG_DEFCON_NO_NEW_NICKS", nickserv_conf.disable_nicks ? "accounts" : "nicknames");
        return 0;
    }

    if (!IsOper(user) && !dict_size(nickserv_handle_dict)) {
	/* Require the first handle registered to belong to someone +o. */
	reply("NSMSG_REQUIRE_OPER");
	return 0;
    }

    if (user->handle_info) {
        reply("NSMSG_USE_RENAME", user->handle_info->handle);
        return 0;
    }

    if (IsRegistering(user)) {
        reply("NSMSG_ALREADY_REGISTERING");
	return 0;
    }

    if (IsStamped(user)) {
        /* Unauthenticated users might still have been stamped
           previously and could therefore have a hidden host;
           do not allow them to register a new account. */
        reply("NSMSG_STAMPED_REGISTER");
        return 0;
    }

    NICKSERV_MIN_PARMS((unsigned)3 + nickserv_conf.email_required);

    if(nickserv_conf.force_handles_lowercase)
        irc_strtolower(argv[1]);
    if (!is_valid_handle(argv[1])) {
        reply("NSMSG_BAD_HANDLE", argv[1]);
        return 0;
    }


    if ((argc >= 4) && nickserv_conf.email_enabled) {
        struct handle_info_list *hil;
        const char *str;

        /* Remember email address. */
        email_addr = argv[3];

        /* Check that the email address looks valid.. */
        if (!valid_email(email_addr)) {
            reply("NSMSG_BAD_EMAIL_ADDR");
            return 0;
        }

        /* .. and that we are allowed to send to it. */
        if ((str = mail_prohibited_address(email_addr))) {
            reply("NSMSG_EMAIL_PROHIBITED", email_addr, str);
            return 0;
        }

        /* If we do email verify, make sure we don't spam the address. */
        if ((hil = dict_find(nickserv_email_dict, email_addr, NULL))) {
            unsigned int nn;
            for (nn=0; nn<hil->used; nn++) {
                if (hil->list[nn]->cookie) {
                    reply("NSMSG_EMAIL_UNACTIVATED");
                    return 0;
                }
            }
            if (hil->used >= nickserv_conf.handles_per_email) {
                reply("NSMSG_EMAIL_OVERUSED");
                return 0;
            }
        }

        no_auth = 1;
    } else {
        email_addr = 0;
        no_auth = 0;
    }

    password = argv[2];
    argv[2] = "****";
    /* Webregister hack - send URL instead of IRC cookie 
     * commands in email
     */
    if((argc >= 5) && !strcmp(argv[4],"WEBLINK"))
        weblink = 1;
    else
        weblink = 0;
    if (!(hi = nickserv_register(user, user, argv[1], password, no_auth)))
        return 0;
    /* Add any masks they should get. */
    if (nickserv_conf.default_hostmask) {
        string_list_append(hi->masks, strdup("*@*"));
    } else {
        string_list_append(hi->masks, generate_hostmask(user, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT));
        if (irc_in_addr_is_valid(user->ip) && !irc_pton(&ip, NULL, user->hostname))
            string_list_append(hi->masks, generate_hostmask(user, GENMASK_OMITNICK|GENMASK_BYIP|GENMASK_NO_HIDING|GENMASK_ANY_IDENT));
    }

    /* If they're the first to register, give them level 1000. */
    if (dict_size(nickserv_handle_dict) == 1) {
        hi->opserv_level = 1000;
        reply("NSMSG_ROOT_HANDLE", argv[1]);
    }

    /* Set their email address. */
    if (email_addr) {
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            int rc;
            if((rc = ldap_do_modify(hi->handle, NULL, email_addr)) != LDAP_SUCCESS) {
                /* Falied to update email in ldap, but still 
                 * updated it here.. what should we do? */
               reply("NSMSG_LDAP_FAIL_EMAIL", ldap_err2string(rc));
            } else {
                nickserv_set_email_addr(hi, email_addr);
            }
        }
        else {
            nickserv_set_email_addr(hi, email_addr);
        }
#else
        nickserv_set_email_addr(hi, email_addr);
#endif
    }

    /* If they need to do email verification, tell them. */
    if (no_auth)
        nickserv_make_cookie(user, hi, ACTIVATION, hi->passwd, weblink);

    /* Set registering flag.. */
    user->modes |= FLAGS_REGISTERING; 

    if (nickserv_conf.sync_log) {
      cryptpass(password, syncpass);
      /*
      * An 0 is only sent if theres no email address. Thios should only happen if email functions are
       * disabled which they wont be for us. Email Required MUST be set on if you are using this.
       * -SiRVulcaN
       */
      SyncLog("REGISTER %s %s %s %s", hi->handle, syncpass, email_addr ? email_addr : "0", user->info);
    }

    /* this wont work if email is required .. */
    process_adduser_pending(user);

    return 1;
}

static NICKSERV_FUNC(cmd_oregister)
{
    struct userNode *settee = NULL;
    struct handle_info *hi;
    char* account = NULL;
    char* pass = NULL;
    char* email = NULL;
    char* mask = NULL;
    char* nick = NULL;

    NICKSERV_MIN_PARMS(3);
   
    account = argv[1];
    pass = argv[2];
    if(nickserv_conf.force_handles_lowercase)
        irc_strtolower(account);
    if (!is_valid_handle(argv[1])) {
        reply("NSMSG_BAD_HANDLE", argv[1]);
        return 0;
    }
    if (nickserv_conf.email_required) {
        NICKSERV_MIN_PARMS(3);
        email = argv[3];
        if (argc > 4) {/* take: "acct pass email mask nick" or "acct pass email mask" or "acct pass email nick" */
            if (strchr(argv[4], '@'))
                mask = argv[4];
            else
                nick = argv[4];
        }
        if (argc >= 6) {
            nick = argv[5];
        }
    }
    else {
        if (argc > 3) {/* take: "account pass mask nick" or "account pass mask" or "account pass nick" */
            if (strchr(argv[3], '@'))
                mask = argv[3];
            else
                nick = argv[3];
        }
        if (argc >= 5) {
            nick = argv[4];
        }
    }
    /* If they passed a nick, look for that user.. */
    if (nick && !(settee = GetUserH(nick))) {
        reply("MSG_NICK_UNKNOWN", argv[4]);
        return 0;
    }
    /* If the setee is already authed, we cant add a 2nd account for them.. */
    if (settee && settee->handle_info) {
        reply("NSMSG_USER_PREV_AUTH", settee->nick);
        return 0;
    }
    /* If there is no default mask in the conf, and they didn't pass a mask, 
     * but we did find a user by nick, generate the mask */
    if (!mask) {
        if (nickserv_conf.default_hostmask)
            mask = "*@*";
        else if (settee)
            mask = generate_hostmask(settee, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT);
        else {
            reply("NSMSG_REGISTER_BAD_NICKMASK");
            return 0;
        }
    }

    if (!(hi = nickserv_register(user, settee, account, pass, 0))) {
        return 0; /* error reply handled by above */
    }
    if (email) {
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            int rc;
            if((rc = ldap_do_modify(hi->handle, NULL, email)) != LDAP_SUCCESS) {
                /* Falied to update email in ldap, but still 
                 * updated it here.. what should we do? */
               reply("NSMSG_LDAP_FAIL_EMAIL", ldap_err2string(rc));
            } else {
                nickserv_set_email_addr(hi, email);
            }
        }
        else {
            nickserv_set_email_addr(hi, email);
        }
#else
        nickserv_set_email_addr(hi, email);
#endif
    }
    if (mask) {
        char* mask_canonicalized = canonicalize_hostmask(strdup(mask));
        if (mask_canonicalized)
            string_list_append(hi->masks, mask_canonicalized);
    }

    argv[2] = "****";

    if (nickserv_conf.sync_log)
        SyncLog("REGISTER %s %s %s %s", hi->handle, hi->passwd, email ? email : "@", user->info); /* Send just @ for email if none */
    return 1;
}

static int
nickserv_ignore(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, char *mask)
{
    unsigned int i;
    struct userNode *target;
    char *new_mask = strdup(pretty_mask(mask));
    for (i=0; i<hi->ignores->used; i++) {
        if (!irccasecmp(new_mask, hi->ignores->list[i])) {
            reply("NSMSG_ADDIGNORE_ALREADY", new_mask);
            free(new_mask);
            return 0;
        }
    }
    string_list_append(hi->ignores, new_mask);
    reply("NSMSG_ADDIGNORE_SUCCESS", new_mask);

    for (target = hi->users; target; target = target->next_authed) {
        irc_silence(target, new_mask, 1);
    }
    return 1;
}

static NICKSERV_FUNC(cmd_addignore)
{
    NICKSERV_MIN_PARMS(2);

    return nickserv_ignore(cmd, user, user->handle_info, argv[1]);
}

static NICKSERV_FUNC(cmd_oaddignore)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;

    return nickserv_ignore(cmd, user, hi, argv[2]);
}

static int
nickserv_delignore(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, char *del_mask)
{
    unsigned int i;
    struct userNode *target;
    char *pmask = strdup(pretty_mask(del_mask));
    for (i=0; i<hi->ignores->used; i++) {
	if (!strcmp(pmask, hi->ignores->list[i]) || !strcmp(del_mask, hi->ignores->list[i])) {
	    char *old_mask = hi->ignores->list[i];
	    hi->ignores->list[i] = hi->ignores->list[--hi->ignores->used];
	    reply("NSMSG_DELMASK_SUCCESS", old_mask);
            for (target = hi->users; target; target = target->next_authed) {
                irc_silence(target, old_mask, 0);
            }
	    free(old_mask);
            free(pmask);
	    return 1;
	}
    }
    reply("NSMSG_DELMASK_NOT_FOUND");
    return 0;
}

static NICKSERV_FUNC(cmd_delignore)
{
    NICKSERV_MIN_PARMS(2);
    return nickserv_delignore(cmd, user, user->handle_info, argv[1]);
}

static NICKSERV_FUNC(cmd_odelignore)
{
    struct handle_info *hi;
    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;
    return nickserv_delignore(cmd, user, hi, argv[2]);
}

static NICKSERV_FUNC(cmd_handleinfo)
{
    char buff[400];
    unsigned int i, pos=0, herelen;
    struct userNode *target, *next_un;
    struct handle_info *hi;
    const char *nsmsg_none;

    if (argc < 2) {
        if (!(hi = user->handle_info)) {
            reply("NSMSG_MUST_AUTH");
            return 0;
        }
    } else if (!(hi = modcmd_get_handle_info(user, argv[1]))) {
        return 0;
    }

    nsmsg_none = handle_find_message(hi, "MSG_NONE");
    reply("NSMSG_HANDLEINFO_ON", hi->handle);
    reply("MSG_BAR");
    reply("NSMSG_HANDLEINFO_REGGED", ctime(&hi->registered));

    if (!hi->users) {
	intervalString(buff, now - hi->lastseen, user->handle_info);
	reply("NSMSG_HANDLEINFO_LASTSEEN", buff);
    } else {
	reply("NSMSG_HANDLEINFO_LASTSEEN_NOW");
    }

    reply("NSMSG_HANDLEINFO_INFOLINE", (hi->infoline ? hi->infoline : nsmsg_none));
    if (HANDLE_FLAGGED(hi, FROZEN))
        reply("NSMSG_HANDLEINFO_VACATION");

    if (oper_has_access(user, cmd->parent->bot, 0, 1)) {
        struct do_not_register *dnr;
        if ((dnr = chanserv_is_dnr(NULL, hi)))
            reply("NSMSG_HANDLEINFO_DNR", dnr->setter, dnr->reason);
        if ((user->handle_info->opserv_level < 900) && !oper_outranks(user, hi))
            return 1;
    } else if (hi != user->handle_info) {
        reply("NSMSG_HANDLEINFO_END");
        return 1;
    }

    if (IsOper(user))
        reply("NSMSG_HANDLEINFO_KARMA", hi->karma);

    if (nickserv_conf.email_enabled)
        reply("NSMSG_HANDLEINFO_EMAIL_ADDR", visible_email_addr(user, hi));

    if (hi->cookie) {
        const char *type;
        switch (hi->cookie->type) {
        case ACTIVATION: type = "NSMSG_HANDLEINFO_COOKIE_ACTIVATION"; break;
        case PASSWORD_CHANGE: type = "NSMSG_HANDLEINFO_COOKIE_PASSWORD"; break;
        case EMAIL_CHANGE: type = "NSMSG_HANDLEINFO_COOKIE_EMAIL"; break;
        case ALLOWAUTH: type = "NSMSG_HANDLEINFO_COOKIE_ALLOWAUTH"; break;
        default: type = "NSMSG_HANDLEINFO_COOKIE_UNKNOWN"; break;
        }
        reply(type);
        if (IsOper(user) && (hi->cookie->type == EMAIL_CHANGE))
            reply("NSMSG_HANDLEINFO_COOKIE_EMAIL_DATA", hi->cookie->data);
    }

    if (hi->flags) {
	unsigned long flen = 1;
	char flags[34]; /* 32 bits possible plus '+' and '\0' */
	flags[0] = '+';
	for (i=0, flen=1; handle_flags[i]; i++)
	    if (hi->flags & 1 << i)
                flags[flen++] = handle_flags[i];
	flags[flen] = 0;
	reply("NSMSG_HANDLEINFO_FLAGS", flags);
    } else {
	reply("NSMSG_HANDLEINFO_FLAGS", nsmsg_none);
    }

    if (hi->opserv_level > 0) {
        reply("NSMSG_HANDLEINFO_OPSERV_LEVEL", hi->opserv_level);
    }

    if (HANDLE_FLAGGED(hi, SUPPORT_HELPER)
        || HANDLE_FLAGGED(hi, NETWORK_HELPER)
        || (hi->opserv_level > 0)) {
        reply("NSMSG_HANDLEINFO_EPITHET", (hi->epithet ? hi->epithet : nsmsg_none));
    }

    if (IsHelping(user) || IsOper(user))
    {
        if (hi->note)
        {
            char date[64];
            strftime(date, 64, "%b %d %Y", localtime(&hi->note->date));
            reply("NSMSG_HANDLEINFO_NOTE", hi->note->setter, date, hi->note->note);
        }
    }

    if (hi->fakehost)
        reply("NSMSG_HANDLEINFO_FAKEHOST", (hi->fakehost ? hi->fakehost : handle_find_message(hi, "MSG_NONE")));

    if (hi->last_quit_host[0])
        reply("NSMSG_HANDLEINFO_LAST_HOST", hi->last_quit_host);
    else
        reply("NSMSG_HANDLEINFO_LAST_HOST_UNKNOWN");

    if (nickserv_conf.disable_nicks) {
	/* nicks disabled; don't show anything about registered nicks */
    } else if (hi->nicks) {
	struct nick_info *ni, *next_ni;
	for (ni = hi->nicks; ni; ni = next_ni) {
	    herelen = strlen(ni->nick);
	    if (pos + herelen + 1 > ArrayLength(buff)) {
		next_ni = ni;
		goto print_nicks_buff;
	    } else {
		next_ni = ni->next;
	    }
	    memcpy(buff+pos, ni->nick, herelen);
	    pos += herelen; buff[pos++] = ' ';
	    if (!next_ni) {
	      print_nicks_buff:
		buff[pos-1] = 0;
		reply("NSMSG_HANDLEINFO_NICKS", buff);
		pos = 0;
	    }
	}
    } else {
	reply("NSMSG_HANDLEINFO_NICKS", nsmsg_none);
    }

    if (hi->masks->used) {
        for (i=0; i < hi->masks->used; i++) {
            herelen = strlen(hi->masks->list[i]);
            if (pos + herelen + 1 > ArrayLength(buff)) {
                i--;
                goto print_mask_buff;
            }
            memcpy(buff+pos, hi->masks->list[i], herelen);
            pos += herelen; buff[pos++] = ' ';
            if (i+1 == hi->masks->used) {
              print_mask_buff:
                buff[pos-1] = 0;
                reply("NSMSG_HANDLEINFO_MASKS", buff);
                pos = 0;
            }
        }
    } else {
        reply("NSMSG_HANDLEINFO_MASKS", nsmsg_none);
    }

    if (hi->sslfps->used) {
        for (i=0; i < hi->sslfps->used; i++) {
            herelen = strlen(hi->sslfps->list[i]);
            if (pos + herelen + 1 > ArrayLength(buff)) {
                i--;
                goto print_sslfp_buff;
            }
            memcpy(buff+pos, hi->sslfps->list[i], herelen);
            pos += herelen; buff[pos++] = ' ';
            if (i+1 == hi->sslfps->used) {
              print_sslfp_buff:
                buff[pos-1] = 0;
                reply("NSMSG_HANDLEINFO_SSLFPS", buff);
                pos = 0;
            }
        }
    } else {
        reply("NSMSG_HANDLEINFO_SSLFPS", nsmsg_none);
    }

    if (hi->ignores->used) {
        for (i=0; i < hi->ignores->used; i++) {
            herelen = strlen(hi->ignores->list[i]);
            if (pos + herelen + 1 > ArrayLength(buff)) {
                i--;
                goto print_ignore_buff;
            }
            memcpy(buff+pos, hi->ignores->list[i], herelen);
            pos += herelen; buff[pos++] = ' ';
            if (i+1 == hi->ignores->used) {
              print_ignore_buff:
                buff[pos-1] = 0;
                reply("NSMSG_HANDLEINFO_IGNORES", buff);
                pos = 0;
            }
        }
    } else {
        reply("NSMSG_HANDLEINFO_IGNORES", nsmsg_none);
    }

    if (hi->channels) {
	struct userData *chan, *next;
	char *name;

        for (chan = hi->channels; chan; chan = next) {
            next = chan->u_next;
            name = chan->channel->channel->name;
	    herelen = strlen(name);
	    if (pos + herelen + 7 > ArrayLength(buff)) {
		next = chan;
                goto print_chans_buff;
	    }
            if (IsUserSuspended(chan))
                buff[pos++] = '-';
            pos += sprintf(buff+pos, "%s:%s ", user_level_name_from_level(chan->access), name);
	    if (next == NULL) {
	      print_chans_buff:
		buff[pos-1] = 0;
		reply("NSMSG_HANDLEINFO_CHANNELS", buff);
		pos = 0;
	    }
	}
    } else {
	reply("NSMSG_HANDLEINFO_CHANNELS", nsmsg_none);
    }

    for (target = hi->users; target; target = next_un) {
	herelen = strlen(target->nick);
	if (pos + herelen + 1 > ArrayLength(buff)) {
	    next_un = target;
	    goto print_cnick_buff;
	} else {
	    next_un = target->next_authed;
	}
	memcpy(buff+pos, target->nick, herelen);
	pos += herelen; buff[pos++] = ' ';
	if (!next_un) {
	  print_cnick_buff:
	    buff[pos-1] = 0;
	    reply("NSMSG_HANDLEINFO_CURRENT", buff);
	    pos = 0;
	}
    }

    reply("NSMSG_HANDLEINFO_END");
    return 1 | ((hi != user->handle_info) ? CMD_LOG_STAFF : 0);
}

static NICKSERV_FUNC(cmd_userinfo)
{
    struct userNode *target;

    NICKSERV_MIN_PARMS(2);
    if (!(target = GetUserH(argv[1]))) {
	reply("MSG_NICK_UNKNOWN", argv[1]);
	return 0;
    }
    if (target->handle_info)
	reply("NSMSG_USERINFO_AUTHED_AS", target->nick, target->handle_info->handle);
    else
	reply("NSMSG_USERINFO_NOT_AUTHED", target->nick);
    return 1;
}

static NICKSERV_FUNC(cmd_nickinfo)
{
    struct nick_info *ni;
    char buff[400];

    NICKSERV_MIN_PARMS(2);
    if (!(ni = get_nick_info(argv[1]))) {
	reply("MSG_NICK_UNKNOWN", argv[1]);
	return 0;
    }

    reply("NSMSG_NICKINFO_ON", ni->nick);
    reply("MSG_BAR");
    reply("NSMSG_NICKINFO_REGGED", ctime(&ni->registered));

    if (!GetUserH(ni->nick)) {
        intervalString(buff, now - ni->lastseen, user->handle_info);
        reply("NSMSG_NICKINFO_LASTSEEN", buff);
    } else {
        reply("NSMSG_NICKINFO_LASTSEEN_NOW");
    }

    reply("NSMSG_NICKINFO_OWNER", ni->owner->handle);

    reply("NSMSG_NICKINFO_END");

    return 1;
}

static NICKSERV_FUNC(cmd_rename_handle)
{
    struct handle_info *hi;
    struct userNode *uNode;
    char *old_handle;
    unsigned int nn;

    NICKSERV_MIN_PARMS(3);
    if(nickserv_conf.force_handles_lowercase)
        irc_strtolower(argv[2]);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;
    if (!is_valid_handle(argv[2])) {
        reply("NSMSG_FAIL_RENAME", argv[1], argv[2]);
        return 0;
    }
    if (get_handle_info(argv[2])) {
        reply("NSMSG_HANDLE_EXISTS", argv[2]);
        return 0;
    }
    if(strlen(argv[2]) > 30)
    {
        reply("NMSG_HANDLE_TOLONG", argv[2], 30);
        return 0;
    }
#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
        int rc;
        if( (rc = ldap_rename_account(hi->handle, argv[2])) != LDAP_SUCCESS) {
            reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
            return 0;
        }
    }
#endif

    dict_remove2(nickserv_handle_dict, old_handle = hi->handle, 1);
    hi->handle = strdup(argv[2]);
    dict_insert(nickserv_handle_dict, hi->handle, hi);
    for (nn=0; nn<rf_list_used; nn++)
        rf_list[nn](hi, old_handle, rf_list_extra[nn]);

    if (nickserv_conf.sync_log) {
        for (uNode = hi->users; uNode; uNode = uNode->next_authed)
            irc_rename(uNode, hi->handle);

        SyncLog("RENAME %s %s", old_handle, hi->handle);
    }

    reply("NSMSG_HANDLE_CHANGED", old_handle, hi->handle);
    global_message_args(MESSAGE_RECIPIENT_OPERS, "NSMSG_ACCOUNT_RENAMED",
                        user->handle_info->handle, old_handle, hi->handle);

    free(old_handle);
    return 1;
}

static failpw_func_t *failpw_func_list;
static void **failpw_func_list_extra;
static unsigned int failpw_func_size = 0, failpw_func_used = 0;

void
reg_failpw_func(failpw_func_t func, void *extra)
{
    if (failpw_func_used == failpw_func_size) {
        if (failpw_func_size) {
            failpw_func_size <<= 1;
            failpw_func_list = realloc(failpw_func_list, failpw_func_size*sizeof(failpw_func_t));
            failpw_func_list_extra = realloc(failpw_func_list_extra, failpw_func_size*sizeof(void*));
        } else {
            failpw_func_size = 8;
            failpw_func_list = malloc(failpw_func_size*sizeof(failpw_func_t));
            failpw_func_list_extra = malloc(failpw_func_size*sizeof(void*));
        }
    }
    failpw_func_list[failpw_func_used] = func;
    failpw_func_list_extra[failpw_func_used++] = extra;
}

/*
 * Return hi for the first handle that has a matching SSL fingerprint.
 */
struct handle_info *find_handleinfo_by_sslfp(char *sslfp)
{
    dict_iterator_t it;
    struct handle_info *hi;
    unsigned int ii = 0;;

    for (it = dict_first(nickserv_handle_dict); it; it = iter_next(it)) {
        hi = iter_data(it);
        for (ii=0; ii<hi->sslfps->used; ii++) {
            if (!irccasecmp(sslfp, hi->sslfps->list[ii])) {
                return hi;
            }
        }
    }

    return NULL;
}

/*
 * Return hi if the handle/pass pair matches, NULL if it doesnt.
 *
 * called by nefariouses enhanced AC login-on-connect code
 *
 */
struct handle_info *loc_auth(char *sslfp, char *handle, char *password, char *userhost)
{
    int wildmask = 0, auth = 0;
    int used, maxlogins;
    unsigned int ii;
    struct handle_info *hi = NULL;
    struct userNode *other;
#ifdef WITH_LDAP
    int ldap_result = LDAP_SUCCESS;
    char *email = NULL;
#endif
    
    if (handle != NULL)
        hi = dict_find(nickserv_handle_dict, handle, NULL);
    if (!hi && (sslfp != NULL)) {
        hi = find_handleinfo_by_sslfp(sslfp);
        if (!handle && (hi != NULL))
            handle = hi->handle;
    }
    
    /* Ensure handle is valid if not found in internal DB */
    if (!hi && (!handle || !is_valid_handle(handle)))
        return 0;

#ifdef WITH_LDAP
    if (nickserv_conf.ldap_enable && (password != NULL)) {
        ldap_result = ldap_check_auth(handle, password);
        if (!hi && (ldap_result != LDAP_SUCCESS))
            return NULL;
        if (ldap_result == LDAP_SUCCESS) {
            /* Mark auth as successful */
            auth++;
        }
    
        if (!hi && (ldap_result == LDAP_SUCCESS) && nickserv_conf.ldap_autocreate) {
            /* user not found, but authed to ldap successfully..
             * create the account.
             */
            char *mask;
            int rc;
            
            /* Add a *@* mask */
            /* TODO if userhost is not null, build mask based on that. */
            if(nickserv_conf.default_hostmask)
               mask = "*@*";
            else
               return NULL; /* They dont have a *@* mask so they can't loc */
    
            if(!(hi = nickserv_register(NULL, NULL, handle, password, 0))) {
               return 0; /* couldn't add the user for some reason */
            }
    
            if((rc = ldap_get_user_info(handle, &email) != LDAP_SUCCESS))
            {
               if(nickserv_conf.email_required) {
                   return 0;
               }
            }
            if(email) {
               nickserv_set_email_addr(hi, email);
               free(email);
            }
            if(mask) {
               char* mask_canonicalized = canonicalize_hostmask(strdup(mask));
               string_list_append(hi->masks, mask_canonicalized);
            }
            if(nickserv_conf.sync_log)
               SyncLog("REGISTER %s %s %s %s", hi->handle, hi->passwd, "@", handle);
        }
    }
#endif

    /* hi should now be a valid handle, if not return NULL */
    if (!hi)
        return NULL;

#ifdef WITH_LDAP
    if (password && *password && !nickserv_conf.ldap_enable) {
#else
    if (password && *password) {
#endif
        if (checkpass(password, hi->passwd))
            auth++;
    }
    
    if (!auth && sslfp && *sslfp && hi->sslfps->used) {
        /* If any SSL fingerprint matches, allow it. */
        for (ii=0; ii<hi->sslfps->used; ii++) {
            if (!irccasecmp(sslfp, hi->sslfps->list[ii])) {
                auth++;
                break;
            }
        }
    }
    
    /* Auth should have succeeded by this point */
    if (!auth)
        return NULL;

    /* We don't know the users hostname, or anything because they
     * havn't registered yet. So we can only allow LOC if your
     * account has *@* as a hostmask.
     *
     * UPDATE: New nefarious LOC supports u@h
     */
    if(userhost) {
        char *buf;
        char *ident = NULL;
        char *realhost = NULL;
        char *ip = NULL;
        char *uh;
        char *ui;
        char *c;
        int bracket = 0;

        buf = strdup(userhost);

        ident = buf;
        for (c = buf; *c; c++) {
            if ((realhost == NULL) && (*c == '@')) {
                *c++ = '\0';
                if (*c == '[') {
                    bracket = 1;
                    *c++ = '\0';
                }
                realhost = c;
            } else if (bracket && (ip == NULL) && (*c == ']')) {
                bracket = 0;
                *c = '\0';
            } else if (!bracket && (ip == NULL) && (*c == ':')) {
                *c++ = '\0';
                ip = c;
                break;
            }
        }

        log_module(NS_LOG, LOG_DEBUG, "LOC: ident=%s host=%s ip=%s", ident, realhost, ip);

        if(!ip || !realhost || !ident) {
            free(buf);
            return NULL; /* Invalid AC request, just quit */
        }
        uh = malloc(strlen(userhost));
        ui = malloc(strlen(userhost));
        sprintf(uh, "%s@%s", ident, realhost);
        sprintf(ui, "%s@%s", ident, ip);
        for (ii=0; ii<hi->masks->used; ii++)
        {
            if(match_ircglob(uh, hi->masks->list[ii])
               || match_ircglob(ui, hi->masks->list[ii]))
            {
                wildmask++;
                break;
            }
        }
        free(buf);
        free(uh);
        free(ui);
    }
    else {

        for (ii=0; ii<hi->masks->used; ii++)
        {
           if (!strcmp(hi->masks->list[ii], "*@*"))
           {
               wildmask++;
               break;
           }
        }
    }
    if(wildmask < 1)
        return NULL;

    if (HANDLE_FLAGGED(hi, SUSPENDED)) {
        return NULL;
    }

    maxlogins = hi->maxlogins ? hi->maxlogins : nickserv_conf.default_maxlogins;
    for (used = 0, other = hi->users; other; other = other->next_authed) {
        if (++used >= maxlogins) {
            return NULL;
        }
    }
    /* TODO - Add LOGGING to this function so LOC's are logged.. */
    return hi;
}

void nickserv_do_autoauth(struct userNode *user)
{
    struct handle_info *hi;
    struct userNode *other;
    int used, maxlogins;

    /* Already authed, nothing to do */
    if (user->handle_info)
        return;

    /* No client certificate fingerprint, cant auto auth */
    if (!user->sslfp)
        return;

    hi = find_handleinfo_by_sslfp(user->sslfp);
    if (!hi)
        return;

    /* User doesn't match host masks */
    if (!valid_user_for(user, hi)) {
        if (hi->email_addr && nickserv_conf.email_enabled)
            send_message_type(4, user, nickserv,
                              handle_find_message(hi, "NSMSG_USE_AUTHCOOKIE"),
                              hi->handle);
        else
            send_message_type(4, user, nickserv,
                              handle_find_message(hi, "NSMSG_HOSTMASK_INVALID"),
                              hi->handle);
        return;
    }

    /* Account suspended? */
    if (HANDLE_FLAGGED(hi, SUSPENDED)) {
        send_message_type(4, user, nickserv,
                          handle_find_message(hi, "NSMSG_HANDLE_SUSPENDED"));
        return;
    }

    maxlogins = hi->maxlogins ? hi->maxlogins : nickserv_conf.default_maxlogins;
    for (used = 0, other = hi->users; other; other = other->next_authed) {
        if (++used >= maxlogins) {
            send_message_type(4, user, nickserv,
                              handle_find_message(hi, "NSMSG_MAX_LOGINS"),
                              maxlogins);
            return;
        }
    }

    set_user_handle_info(user, hi, 1);
    if (nickserv_conf.email_required && !hi->email_addr)
        send_message_type(4, user, nickserv,
                          handle_find_message(hi, "NSMSG_PLEASE_SET_EMAIL"));

   /* If a channel was waiting for this user to auth,
    * finish adding them */
    process_adduser_pending(user);

    send_message_type(4, user, nickserv,
                      handle_find_message(hi, "NSMSG_AUTH_SUCCESS"));

    /* Set +x if autohide is on */
    if(HANDLE_FLAGGED(hi, AUTOHIDE))
        irc_umode(user, "+x");
}

static NICKSERV_FUNC(cmd_auth)
{
    int pw_arg, used, maxlogins;
    int sslfpauth = 0;
    struct handle_info *hi;
    const char *passwd;
    const char *handle;
    struct userNode *other;
#ifdef WITH_LDAP
    int ldap_result = LDAP_OTHER;
    char *email = NULL;
#endif

    if (user->handle_info) {
        reply("NSMSG_ALREADY_AUTHED", user->handle_info->handle);
        return 0;
    }
    if (IsStamped(user)) {
        /* Unauthenticated users might still have been stamped
           previously and could therefore have a hidden host;
           do not allow them to authenticate. */
        reply("NSMSG_STAMPED_AUTH");
        return 0;
    }
    if (argc == 3) {
        passwd = argv[2];
        handle = argv[1];
        pw_arg = 2;
        hi = dict_find(nickserv_handle_dict, argv[1], NULL);
    } else if (argc == 2) {
        passwd = argv[1];
        pw_arg = 1;
        if (nickserv_conf.disable_nicks) {
            hi = get_handle_info(user->nick);
        } else {
            /* try to look up their handle from their nick */
            /* TODO: handle ldap auth on nickserv style networks, too */
            struct nick_info *ni;
            ni = get_nick_info(user->nick);
            if (!ni) {
                reply("NSMSG_NICK_NOT_REGISTERED", user->nick);
                return 0;
            }
            hi = ni->owner;
        }
        if (hi) {
            handle = hi->handle;
        } else {
            handle = user->nick;
        }
    } else {
        reply("MSG_MISSING_PARAMS", argv[0]);
        svccmd_send_help_brief(user, nickserv, cmd);
        return 0;
    }
    
#ifdef WITH_LDAP
    if(strchr(handle, '<') || strchr(handle, '>')) {
        reply("NSMSG_NO_ANGLEBRACKETS");
        return 0;
    }
    if (!is_valid_handle(handle)) {
        reply("NSMSG_BAD_HANDLE", handle);
        return 0;
    }

    if(nickserv_conf.ldap_enable) {
        ldap_result = ldap_check_auth(handle, passwd);
        /* Get the users email address and update it */
        if(ldap_result == LDAP_SUCCESS) {
           int rc;
           if((rc = ldap_get_user_info(handle, &email) != LDAP_SUCCESS))
           {
                if(nickserv_conf.email_required) {
                    reply("NSMSG_LDAP_FAIL_GET_EMAIL", ldap_err2string(rc));
                    return 0;
                }
           }
        }
        else if(ldap_result != LDAP_INVALID_CREDENTIALS) {
           reply("NSMSG_LDAP_FAIL", ldap_err2string(ldap_result));
           return 0;
        }
    }
#endif

    if (!hi) {
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && ldap_result == LDAP_SUCCESS && nickserv_conf.ldap_autocreate) {
           /* user not found, but authed to ldap successfully..
            * create the account.
            */
             char *mask;
             if(!(hi = nickserv_register(user, user, handle, passwd, 0))) {
                reply("NSMSG_UNABLE_TO_ADD");
                return 0; /* couldn't add the user for some reason */
             }
             /* Add a *@* mask */
             if(nickserv_conf.default_hostmask)
                mask = "*@*";
             else
                mask = generate_hostmask(user, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT);

             if(mask) {
                char* mask_canonicalized = canonicalize_hostmask(strdup(mask));
                string_list_append(hi->masks, mask_canonicalized);
             }
             if(email) {
                nickserv_set_email_addr(hi, email);
                free(email);
             }
             if(nickserv_conf.sync_log)
                SyncLog("REGISTER %s %s %s %s", hi->handle, hi->passwd, email ? email : "@", user->info);
        }
        else {
#endif
             reply("NSMSG_HANDLE_NOT_FOUND");
             return 0;
#ifdef WITH_LDAP
        }
#endif
    }
    /* Responses from here on look up the language used by the handle they asked about. */
    if (!valid_user_for(user, hi)) {
        if (hi->email_addr && nickserv_conf.email_enabled)
            send_message_type(4, user, cmd->parent->bot,
                              handle_find_message(hi, "NSMSG_USE_AUTHCOOKIE"),
                              hi->handle);
        else
            send_message_type(4, user, cmd->parent->bot,
                              handle_find_message(hi, "NSMSG_HOSTMASK_INVALID"),
                              hi->handle);
        argv[pw_arg] = "BADMASK";
        return 1;
    }

    if (valid_user_sslfp(user, hi))
        sslfpauth = 1;

#ifdef WITH_LDAP
    if(( ( nickserv_conf.ldap_enable && ldap_result == LDAP_INVALID_CREDENTIALS )  ||
        ( (!nickserv_conf.ldap_enable) && (!checkpass(passwd, hi->passwd)) ) ) && !sslfpauth) {
#else
    if (!checkpass(passwd, hi->passwd) && !sslfpauth) {
#endif
        unsigned int n;
        send_message_type(4, user, cmd->parent->bot,
                          handle_find_message(hi, "NSMSG_PASSWORD_INVALID"));
        argv[pw_arg] = "BADPASS";
        for (n=0; n<failpw_func_used; n++)
            failpw_func_list[n](user, hi, failpw_func_list_extra[n]);
        if (nickserv_conf.autogag_enabled) {
            if (!user->auth_policer.params) {
                user->auth_policer.last_req = now;
                user->auth_policer.params = nickserv_conf.auth_policer_params;
            }
            if (!policer_conforms(&user->auth_policer, now, 1.0)) {
                char *hostmask;
                hostmask = generate_hostmask(user, GENMASK_STRICT_HOST|GENMASK_BYIP|GENMASK_NO_HIDING);
                log_module(NS_LOG, LOG_INFO, "%s auto-gagged for repeated password guessing.", hostmask);
                gag_create(hostmask, nickserv->nick, "Repeated password guessing.", now+nickserv_conf.autogag_duration);
                free(hostmask);
                argv[pw_arg] = "GAGGED";
            }
        }
        return 1;
    }
    if (HANDLE_FLAGGED(hi, SUSPENDED)) {
        send_message_type(4, user, cmd->parent->bot,
                          handle_find_message(hi, "NSMSG_HANDLE_SUSPENDED"));
        argv[pw_arg] = "SUSPENDED";
        return 1;
    }
    maxlogins = hi->maxlogins ? hi->maxlogins : nickserv_conf.default_maxlogins;
    for (used = 0, other = hi->users; other; other = other->next_authed) {
        if (++used >= maxlogins) {
            send_message_type(4, user, cmd->parent->bot,
                              handle_find_message(hi, "NSMSG_MAX_LOGINS"),
                              maxlogins);
            argv[pw_arg] = "MAXLOGINS";
            return 1;
        }
    }

    set_user_handle_info(user, hi, 1);
    if (nickserv_conf.email_required && !hi->email_addr)
        reply("NSMSG_PLEASE_SET_EMAIL");
    if (!sslfpauth && !is_secure_password(hi->handle, passwd, NULL))
        reply("NSMSG_WEAK_PASSWORD");
    if (!sslfpauth && (hi->passwd[0] != '$'))
        cryptpass(passwd, hi->passwd);

   /* If a channel was waiting for this user to auth, 
    * finish adding them */
    process_adduser_pending(user);

    reply("NSMSG_AUTH_SUCCESS");

    
    /* Set +x if autohide is on */
    if(HANDLE_FLAGGED(hi, AUTOHIDE))
        irc_umode(user, "+x");

    if (!hi->masks->used) {
        irc_in_addr_t ip;
        string_list_append(hi->masks, generate_hostmask(user, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT));
        if (irc_in_addr_is_valid(user->ip) && irc_pton(&ip, NULL, user->hostname))
            string_list_append(hi->masks, generate_hostmask(user, GENMASK_OMITNICK|GENMASK_BYIP|GENMASK_NO_HIDING|GENMASK_ANY_IDENT));
    }

    /* Wipe out the pass for the logs */
    argv[pw_arg] = "****";
    return 1;
}

static allowauth_func_t *allowauth_func_list;
static void **allowauth_func_list_extra;
static unsigned int allowauth_func_size = 0, allowauth_func_used = 0;

void
reg_allowauth_func(allowauth_func_t func, void *extra)
{
    if (allowauth_func_used == allowauth_func_size) {
        if (allowauth_func_size) {
            allowauth_func_size <<= 1;
            allowauth_func_list = realloc(allowauth_func_list, allowauth_func_size*sizeof(allowauth_func_t));
            allowauth_func_list_extra = realloc(allowauth_func_list_extra, allowauth_func_size*sizeof(void*));
        } else {
            allowauth_func_size = 8;
            allowauth_func_list = malloc(allowauth_func_size*sizeof(allowauth_func_t));
            allowauth_func_list_extra = malloc(allowauth_func_size*sizeof(void*));
        }
    }
    allowauth_func_list[allowauth_func_used] = func;
    allowauth_func_list_extra[allowauth_func_used++] = extra;
}

static NICKSERV_FUNC(cmd_allowauth)
{
    struct userNode *target;
    struct handle_info *hi;
    unsigned int n;

    NICKSERV_MIN_PARMS(2);
    if (!(target = GetUserH(argv[1]))) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    if (target->handle_info) {
        reply("NSMSG_USER_PREV_AUTH", target->nick);
        return 0;
    }
    if (IsStamped(target)) {
        /* Unauthenticated users might still have been stamped
           previously and could therefore have a hidden host;
           do not allow them to authenticate to an account. */
        reply("NSMSG_USER_PREV_STAMP", target->nick);
        return 0;
    }
    if (argc == 2)
        hi = NULL;
    else if (!(hi = get_handle_info(argv[2]))) {
        reply("MSG_HANDLE_UNKNOWN", argv[2]);
        return 0;
    }
    if (hi) {
        if (hi->opserv_level > user->handle_info->opserv_level) {
            reply("MSG_USER_OUTRANKED", hi->handle);
            return 0;
        }
        if (((hi->flags & (HI_FLAG_SUPPORT_HELPER|HI_FLAG_NETWORK_HELPER))
             || (hi->opserv_level > 0))
            && ((argc < 4) || irccasecmp(argv[3], "staff"))) {
            reply("NSMSG_ALLOWAUTH_STAFF", hi->handle);
            return 0;
        }
        dict_insert(nickserv_allow_auth_dict, target->nick, hi);
        reply("NSMSG_AUTH_ALLOWED", target->nick, hi->handle);
        send_message(target, nickserv, "NSMSG_AUTH_ALLOWED_MSG", hi->handle, hi->handle);
        if (nickserv_conf.email_enabled)
            send_message(target, nickserv, "NSMSG_AUTH_ALLOWED_EMAIL");
    } else {
        if (dict_remove(nickserv_allow_auth_dict, target->nick))
            reply("NSMSG_AUTH_NORMAL_ONLY", target->nick);
        else
            reply("NSMSG_AUTH_UNSPECIAL", target->nick);
    }
    for (n=0; n<allowauth_func_used; n++)
        allowauth_func_list[n](user, target, hi, allowauth_func_list_extra[n]);
    return 1;
}

static NICKSERV_FUNC(cmd_authcookie)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(2);
    if (user->handle_info) {
        reply("NSMSG_ALREADY_AUTHED", user->handle_info->handle);
        return 0;
    }
    if (IsStamped(user)) {
        /* Unauthenticated users might still have been stamped
           previously and could therefore have a hidden host;
           do not allow them to authenticate to an account. */
        reply("NSMSG_STAMPED_AUTHCOOKIE");
        return 0;
    }
    if (!(hi = get_handle_info(argv[1]))) {
        reply("MSG_HANDLE_UNKNOWN", argv[1]);
        return 0;
    }
    if (!hi->email_addr) {
        reply("MSG_SET_EMAIL_ADDR");
        return 0;
    }
    nickserv_make_cookie(user, hi, ALLOWAUTH, NULL, 0);
    return 1;
}

static NICKSERV_FUNC(cmd_delcookie)
{
    struct handle_info *hi;

    hi = user->handle_info;
    if (!hi->cookie) {
        reply("NSMSG_NO_COOKIE");
        return 0;
    }
    switch (hi->cookie->type) {
    case ACTIVATION:
    case EMAIL_CHANGE:
        reply("NSMSG_MUST_TIME_OUT");
        break;
    default:
        nickserv_eat_cookie(hi->cookie);
        reply("NSMSG_ATE_COOKIE");
        break;
    }
    return 1;
}

static NICKSERV_FUNC(cmd_odelcookie)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(2);

    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;

    if (!hi->cookie) {
        reply("NSMSG_NO_COOKIE_FOREIGN", hi->handle);
        return 0;
    }

    switch (hi->cookie->type) {
    case ACTIVATION:
        safestrncpy(hi->passwd, hi->cookie->data, sizeof(hi->passwd));
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            int rc;
            if((rc = ldap_do_modify(hi->handle, hi->cookie->data, NULL)) != LDAP_SUCCESS) {
                /* Falied to update password in ldap, but still
                 * updated it here.. what should we do? */
               reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
               return 0;
            }
        }
#endif
        if (nickserv_conf.sync_log)
          SyncLog("ACCOUNTACC %s", hi->handle);
        break;
    case PASSWORD_CHANGE:
        break;
    case EMAIL_CHANGE:
        break;
    case ALLOWAUTH:
	break;
    default:
        reply("NSMSG_BAD_COOKIE_TYPE", hi->cookie->type);
        log_module(NS_LOG, LOG_ERROR, "Bad cookie type %d for account %s.", hi->cookie->type, hi->handle);
        break;
    }

    nickserv_eat_cookie(hi->cookie);
    reply("NSMSG_ATE_FOREIGN_COOKIE", hi->handle);

    return 1;
}

static NICKSERV_FUNC(cmd_resetpass)
{
    struct handle_info *hi;
    char crypted[MD5_CRYPT_LENGTH];
    int weblink;

    NICKSERV_MIN_PARMS(3);
    if(argc >= 4 && !strcmp(argv[3], "WEBLINK"))
        weblink = 1;
    else
        weblink = 0;
    if (user->handle_info) {
        reply("NSMSG_ALREADY_AUTHED", user->handle_info->handle);
        return 0;
    }
    if (IsStamped(user)) {
        /* Unauthenticated users might still have been stamped
           previously and could therefore have a hidden host;
           do not allow them to activate an account. */
        reply("NSMSG_STAMPED_RESETPASS");
        return 0;
    }
    if (!(hi = get_handle_info(argv[1]))) {
        reply("MSG_HANDLE_UNKNOWN", argv[1]);
        return 0;
    }
    if (!hi->email_addr) {
        reply("MSG_SET_EMAIL_ADDR");
        return 0;
    }
    cryptpass(argv[2], crypted);
    argv[2] = "****";
    nickserv_make_cookie(user, hi, PASSWORD_CHANGE, crypted, weblink);
    return 1;
}

static NICKSERV_FUNC(cmd_cookie)
{
    struct handle_info *hi;
    const char *cookie;

    if ((argc == 2) && (hi = user->handle_info) && hi->cookie && (hi->cookie->type == EMAIL_CHANGE)) {
        cookie = argv[1];
    } else {
        NICKSERV_MIN_PARMS(3);
        if (!(hi = get_handle_info(argv[1]))) {
            reply("MSG_HANDLE_UNKNOWN", argv[1]);
            return 0;
        }
        cookie = argv[2];
    }

    if (HANDLE_FLAGGED(hi, SUSPENDED)) {
        reply("NSMSG_HANDLE_SUSPENDED");
        return 0;
    }

    if (!hi->cookie) {
        reply("NSMSG_NO_COOKIE");
        return 0;
    }

    /* Check validity of operation before comparing cookie to
     * prohibit guessing by authed users. */
    if (user->handle_info
        && (hi->cookie->type != EMAIL_CHANGE)
        && (hi->cookie->type != PASSWORD_CHANGE)) {
        reply("NSMSG_CANNOT_COOKIE");
        return 0;
    }

    if (strcmp(cookie, hi->cookie->cookie)) {
        reply("NSMSG_BAD_COOKIE");
        return 0;
    }

    switch (hi->cookie->type) {
    case ACTIVATION:
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            int rc;
            if((rc = ldap_do_modify(hi->handle, hi->cookie->data, NULL)) != LDAP_SUCCESS) {
                /* Falied to update email in ldap, but still 
                 * updated it here.. what should we do? */
               reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
               return 0;
            }
        }
#endif
        safestrncpy(hi->passwd, hi->cookie->data, sizeof(hi->passwd));
        set_user_handle_info(user, hi, 1);
        reply("NSMSG_HANDLE_ACTIVATED");
        if (nickserv_conf.sync_log)
          SyncLog("ACCOUNTACC %s", hi->handle);
        break;
    case PASSWORD_CHANGE:
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            int rc;
            if((rc = ldap_do_modify(hi->handle, hi->cookie->data, NULL)) != LDAP_SUCCESS) {
                /* Falied to update email in ldap, but still 
                 * updated it here.. what should we do? */
               reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
               return 0;
            }
        }
#endif
        set_user_handle_info(user, hi, 1);
        safestrncpy(hi->passwd, hi->cookie->data, sizeof(hi->passwd));
        reply("NSMSG_PASSWORD_CHANGED");
        if (nickserv_conf.sync_log)
          SyncLog("PASSCHANGE %s %s", hi->handle, hi->passwd);
        break;
    case EMAIL_CHANGE:
#ifdef WITH_LDAP
        if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
            int rc;
            if((rc = ldap_do_modify(hi->handle, NULL, hi->cookie->data)) != LDAP_SUCCESS) {
                /* Falied to update email in ldap, but still 
                 * updated it here.. what should we do? */
               reply("NSMSG_LDAP_FAIL_SEND_EMAIL", ldap_err2string(rc));
               return 0;
            }
        }
#endif
        if (!hi->email_addr && nickserv_conf.sync_log) {
          /*
           * This should only happen if an OREGISTER was sent. Require
           * email must be enabled! - SiRVulcaN
           */
          if (nickserv_conf.sync_log)
            SyncLog("REGISTER %s %s %s %s", hi->handle, hi->passwd, hi->cookie->data, user->info);
        }

        nickserv_set_email_addr(hi, hi->cookie->data);
        reply("NSMSG_EMAIL_CHANGED");
        if (nickserv_conf.sync_log)
          SyncLog("EMAILCHANGE %s %s", hi->handle, hi->cookie->data);
        break;
    case ALLOWAUTH: {
        char *mask = generate_hostmask(user, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT);
        set_user_handle_info(user, hi, 1);
        nickserv_addmask(user, hi, mask);
        reply("NSMSG_AUTH_SUCCESS");
        free(mask);
        break;
    }
    default:
        reply("NSMSG_BAD_COOKIE_TYPE", hi->cookie->type);
        log_module(NS_LOG, LOG_ERROR, "Bad cookie type %d for account %s.", hi->cookie->type, hi->handle);
        break;
    }

    nickserv_eat_cookie(hi->cookie);

    process_adduser_pending(user);

    return 1;
}

static NICKSERV_FUNC(cmd_oregnick) {
    const char *nick;
    struct handle_info *target;
    struct nick_info *ni;

    NICKSERV_MIN_PARMS(3);
    if (!(target = modcmd_get_handle_info(user, argv[1])))
        return 0;
    nick = argv[2];
    if (!is_registerable_nick(nick)) {
        reply("NSMSG_BAD_NICK", nick);
        return 0;
    }
    ni = dict_find(nickserv_nick_dict, nick, NULL);
    if (ni) {
	reply("NSMSG_NICK_EXISTS", nick);
	return 0;
    }
    register_nick(nick, target);
    reply("NSMSG_OREGNICK_SUCCESS", nick, target->handle);
    return 1;
}

static NICKSERV_FUNC(cmd_regnick) {
    unsigned n;
    struct nick_info *ni;

    if (!is_registerable_nick(user->nick)) {
        reply("NSMSG_BAD_NICK", user->nick);
        return 0;
    }
    /* count their nicks, see if it's too many */
    for (n=0,ni=user->handle_info->nicks; ni; n++,ni=ni->next) ;
    if (n >= nickserv_conf.nicks_per_handle) {
        reply("NSMSG_TOO_MANY_NICKS");
        return 0;
    }
    ni = dict_find(nickserv_nick_dict, user->nick, NULL);
    if (ni) {
	reply("NSMSG_NICK_EXISTS", user->nick);
	return 0;
    }
    register_nick(user->nick, user->handle_info);
    reply("NSMSG_REGNICK_SUCCESS", user->nick);
    return 1;
}

static NICKSERV_FUNC(cmd_pass)
{
    struct handle_info *hi;
    char *old_pass, *new_pass;
    char crypted[MD5_CRYPT_LENGTH+1];
#ifdef WITH_LDAP
    int ldap_result;
#endif

    NICKSERV_MIN_PARMS(3);
    hi = user->handle_info;
    old_pass = argv[1];
    new_pass = argv[2];
    argv[2] = "****";
    if (!is_secure_password(hi->handle, new_pass, user)) return 0;

#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable) {
        ldap_result = ldap_check_auth(hi->handle, old_pass);
        if(ldap_result != LDAP_SUCCESS) {
            if(ldap_result == LDAP_INVALID_CREDENTIALS) 
	       reply("NSMSG_PASSWORD_INVALID");
            else
               reply("NSMSG_LDAP_FAIL", ldap_err2string(ldap_result));
           return 0;
        }
    }else
#endif
    if (!checkpass(old_pass, hi->passwd)) {
        argv[1] = "BADPASS";
	reply("NSMSG_PASSWORD_INVALID");
	return 0;
    }
    cryptpass(new_pass, crypted);
#ifdef WITH_LDAP   
    if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
        int rc;
        if((rc = ldap_do_modify(hi->handle, crypted, NULL)) != LDAP_SUCCESS) {
             reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
             return 0;
        }
    }
#endif
    //cryptpass(new_pass, hi->passwd);
    strcpy(hi->passwd, crypted);
    if (nickserv_conf.sync_log)
      SyncLog("PASSCHANGE %s %s", hi->handle, hi->passwd);
    argv[1] = "****";
    reply("NSMSG_PASS_SUCCESS");
    return 1;
}

static int
nickserv_addmask(struct userNode *user, struct handle_info *hi, const char *mask)
{
    unsigned int i;
    char *new_mask = canonicalize_hostmask(strdup(mask));
    for (i=0; i<hi->masks->used; i++) {
        if (!irccasecmp(new_mask, hi->masks->list[i])) {
            send_message(user, nickserv, "NSMSG_ADDMASK_ALREADY", new_mask);
            free(new_mask);
            return 0;
        }
    }
    string_list_append(hi->masks, new_mask);
    send_message(user, nickserv, "NSMSG_ADDMASK_SUCCESS", new_mask);
    return 1;
}

static NICKSERV_FUNC(cmd_addmask)
{
    if (argc < 2) {
        char *mask = generate_hostmask(user, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT);
        int res = nickserv_addmask(user, user->handle_info, mask);
        free(mask);
        return res;
    } else {
        if (!is_gline(argv[1])) {
            reply("NSMSG_MASK_INVALID", argv[1]);
            return 0;
        }
        return nickserv_addmask(user, user->handle_info, argv[1]);
    }
}

static NICKSERV_FUNC(cmd_oaddmask)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;
    return nickserv_addmask(user, hi, argv[2]);
}

static int
nickserv_delmask(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, const char *del_mask, int force)
{
    unsigned int i;
    for (i=0; i<hi->masks->used; i++) {
	if (!strcmp(del_mask, hi->masks->list[i])) {
	    char *old_mask = hi->masks->list[i];
	    if (hi->masks->used == 1 && !force) {
		reply("NSMSG_DELMASK_NOTLAST");
		return 0;
	    }
	    hi->masks->list[i] = hi->masks->list[--hi->masks->used];
	    reply("NSMSG_DELMASK_SUCCESS", old_mask);
	    free(old_mask);
	    return 1;
	}
    }
    reply("NSMSG_DELMASK_NOT_FOUND");
    return 0;
}

static NICKSERV_FUNC(cmd_delmask)
{
    NICKSERV_MIN_PARMS(2);
    return nickserv_delmask(cmd, user, user->handle_info, argv[1], 0);
}

static NICKSERV_FUNC(cmd_odelmask)
{
    struct handle_info *hi;
    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;
    return nickserv_delmask(cmd, user, hi, argv[2], 1);
}

static int
nickserv_addsslfp(struct userNode *user, struct handle_info *hi, const char *sslfp)
{
    unsigned int i;
    char *new_sslfp = strdup(sslfp);
    for (i=0; i<hi->sslfps->used; i++) {
        if (!irccasecmp(new_sslfp, hi->sslfps->list[i])) {
            send_message(user, nickserv, "NSMSG_ADDSSLFP_ALREADY", new_sslfp);
            free(new_sslfp);
            return 0;
        }
    }
    string_list_append(hi->sslfps, new_sslfp);
    send_message(user, nickserv, "NSMSG_ADDSSLFP_SUCCESS", new_sslfp);
    return 1;
}

static NICKSERV_FUNC(cmd_addsslfp)
{
	NICKSERV_MIN_PARMS((user->sslfp ? 1 : 2));
    if ((argc < 2) && (user->sslfp)) {
        int res = nickserv_addsslfp(user, user->handle_info, user->sslfp);
        return res;
    } else {
        return nickserv_addsslfp(user, user->handle_info, argv[1]);
    }
}

static NICKSERV_FUNC(cmd_oaddsslfp)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;
    return nickserv_addsslfp(user, hi, argv[2]);
}

static int
nickserv_delsslfp(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, const char *del_sslfp)
{
    unsigned int i;
    for (i=0; i<hi->sslfps->used; i++) {
        if (!irccasecmp(del_sslfp, hi->sslfps->list[i])) {
            char *old_sslfp = hi->sslfps->list[i];
            hi->sslfps->list[i] = hi->sslfps->list[--hi->sslfps->used];
            reply("NSMSG_DELSSLFP_SUCCESS", old_sslfp);
            free(old_sslfp);
            return 1;
        }
    }
    reply("NSMSG_DELSSLFP_NOT_FOUND");
    return 0;
}

static NICKSERV_FUNC(cmd_delsslfp)
{
    NICKSERV_MIN_PARMS((user->sslfp ? 1 : 2));
    if ((argc < 2) && (user->sslfp)) {
        return nickserv_delsslfp(cmd, user, user->handle_info, user->sslfp);
    } else {
        return nickserv_delsslfp(cmd, user, user->handle_info, argv[1]);
    }
}

static NICKSERV_FUNC(cmd_odelsslfp)
{
    struct handle_info *hi;
    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;
    return nickserv_delsslfp(cmd, user, hi, argv[2]);
}

int
nickserv_modify_handle_flags(struct userNode *user, struct userNode *bot, const char *str, unsigned long *padded, unsigned long *premoved) {
    unsigned int nn, add = 1, pos;
    unsigned long added, removed, flag;

    for (added=removed=nn=0; str[nn]; nn++) {
	switch (str[nn]) {
	case '+': add = 1; break;
	case '-': add = 0; break;
	default:
	    if (!(pos = handle_inverse_flags[(unsigned char)str[nn]])) {
		send_message(user, bot, "NSMSG_INVALID_FLAG", str[nn]);
		return 0;
	    }
            if (user && (user->handle_info->opserv_level < flag_access_levels[pos-1])) {
                /* cheesy avoidance of looking up the flag name.. */
                send_message(user, bot, "NSMSG_FLAG_PRIVILEGED", str[nn]);
                return 0;
            }
            flag = 1 << (pos - 1);
	    if (add)
                added |= flag, removed &= ~flag;
	    else
                removed |= flag, added &= ~flag;
	    break;
	}
    }
    *padded = added;
    *premoved = removed;
    return 1;
}

static int
nickserv_apply_flags(struct userNode *user, struct handle_info *hi, const char *flags)
{
    unsigned long before, after, added, removed;
    struct userNode *uNode;

    before = hi->flags & (HI_FLAG_SUPPORT_HELPER|HI_FLAG_NETWORK_HELPER);
    if (!nickserv_modify_handle_flags(user, nickserv, flags, &added, &removed))
        return 0;
    hi->flags = (hi->flags | added) & ~removed;
    after = hi->flags & (HI_FLAG_SUPPORT_HELPER|HI_FLAG_NETWORK_HELPER);

    /* Strip helping flag if they're only a support helper and not
     * currently in #support. */
    if (HANDLE_FLAGGED(hi, HELPING) && (after == HI_FLAG_SUPPORT_HELPER)) {
        struct channelList *schannels;
        unsigned int ii;
        schannels = chanserv_support_channels();
        for (ii = 0; ii < schannels->used; ++ii)
            if (find_handle_in_channel(schannels->list[ii], hi, NULL))
                break;
        if (ii == schannels->used)
            HANDLE_CLEAR_FLAG(hi, HELPING);
    }

    if (after && !before) {
        /* Add user to current helper list. */
        for (uNode = hi->users; uNode; uNode = uNode->next_authed)
            userList_append(&curr_helpers, uNode);
    } else if (!after && before) {
        /* Remove user from current helper list. */
        for (uNode = hi->users; uNode; uNode = uNode->next_authed)
            userList_remove(&curr_helpers, uNode);
    }

    return 1;
}

static void
set_list(struct svccmd *cmd, struct userNode *user, struct handle_info *hi, int override)
{
    option_func_t *opt;
    unsigned int i;
    char *set_display[] = {
        "INFO", "WIDTH", "TABLEWIDTH", "COLOR", "PRIVMSG", "STYLE",
        "EMAIL", "ANNOUNCEMENTS", "AUTOHIDE", "MAXLOGINS", "LANGUAGE",
        "FAKEHOST", "TITLE", "EPITHET", "ADVANCED"
    };

    reply("NSMSG_SETTING_LIST");
    reply("NSMSG_SETTING_LIST_HEADER");

    /* Do this so options are presented in a consistent order. */
    for (i = 0; i < ArrayLength(set_display); ++i)
	if ((opt = dict_find(nickserv_opt_dict, set_display[i], NULL)))
	    opt(cmd, user, hi, override, 0, 0, NULL);
    reply("NSMSG_SETTING_LIST_END");
}

static NICKSERV_FUNC(cmd_set)
{
    struct handle_info *hi;
    option_func_t *opt;

    hi = user->handle_info;
    if (argc < 2) {
	set_list(cmd, user, hi, 0);
	return 1;
    }
    if (!(opt = dict_find(nickserv_opt_dict, argv[1], NULL))) {
	reply("NSMSG_INVALID_OPTION", argv[1]);
        return 0;
    }
    return opt(cmd, user, hi, 0, 0, argc-1, argv+1);
}

static NICKSERV_FUNC(cmd_oset)
{
    struct handle_info *hi;
    option_func_t *opt;

    NICKSERV_MIN_PARMS(2);

    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;

    if (argc < 3) {
	set_list(cmd, user, hi, 0);
	return 1;
    }

    if (!(opt = dict_find(nickserv_opt_dict, argv[2], NULL))) {
	reply("NSMSG_INVALID_OPTION", argv[2]);
        return 0;
    }

    return opt(cmd, user, hi, 1, 0, argc-2, argv+2);
}

static OPTION_FUNC(opt_info)
{
    const char *info;
    if (argc > 1) {
	if ((argv[1][0] == '*') && (argv[1][1] == 0)) {
            free(hi->infoline);
            hi->infoline = NULL;
	} else {
	    hi->infoline = strdup(unsplit_string(argv+1, argc-1, NULL));
	}
    }

    info = hi->infoline ? hi->infoline : user_find_message(user, "MSG_NONE");
    if (!(noreply))
        reply("NSMSG_SET_INFO", info);
    return 1;
}

static OPTION_FUNC(opt_width)
{
    if (argc > 1)
	hi->screen_width = strtoul(argv[1], NULL, 0);

    if ((hi->screen_width > 0) && (hi->screen_width < MIN_LINE_SIZE))
        hi->screen_width = MIN_LINE_SIZE;
    else if (hi->screen_width > MAX_LINE_SIZE)
        hi->screen_width = MAX_LINE_SIZE;

    if (!(noreply))
        reply("NSMSG_SET_WIDTH", hi->screen_width);
    return 1;
}

static OPTION_FUNC(opt_tablewidth)
{
    if (argc > 1)
	hi->table_width = strtoul(argv[1], NULL, 0);

    if ((hi->table_width > 0) && (hi->table_width < MIN_LINE_SIZE))
        hi->table_width = MIN_LINE_SIZE;
    else if (hi->screen_width > MAX_LINE_SIZE)
        hi->table_width = MAX_LINE_SIZE;

    if (!(noreply))
        reply("NSMSG_SET_TABLEWIDTH", hi->table_width);
    return 1;
}

static OPTION_FUNC(opt_color)
{
    if (argc > 1) {
	if (enabled_string(argv[1]))
	    HANDLE_SET_FLAG(hi, MIRC_COLOR);
        else if (disabled_string(argv[1]))
	    HANDLE_CLEAR_FLAG(hi, MIRC_COLOR);
	else {
            if (!(noreply))
	        reply("MSG_INVALID_BINARY", argv[1]);
	    return 0;
	}
    }

    if (!(noreply))
        reply("NSMSG_SET_COLOR", user_find_message(user, HANDLE_FLAGGED(hi, MIRC_COLOR) ? "MSG_ON" : "MSG_OFF"));
    return 1;
}

static OPTION_FUNC(opt_privmsg)
{
    if (argc > 1) {
	if (enabled_string(argv[1]))
	    HANDLE_SET_FLAG(hi, USE_PRIVMSG);
        else if (disabled_string(argv[1]))
	    HANDLE_CLEAR_FLAG(hi, USE_PRIVMSG);
	else {
            if (!(noreply))
	        reply("MSG_INVALID_BINARY", argv[1]);
	    return 0;
	}
    }

    if (!(noreply))
        reply("NSMSG_SET_PRIVMSG", user_find_message(user, HANDLE_FLAGGED(hi, USE_PRIVMSG) ? "MSG_ON" : "MSG_OFF"));
    return 1;
}

static OPTION_FUNC(opt_autohide)
{
    if (argc > 1) {
	if (enabled_string(argv[1]))
	    HANDLE_SET_FLAG(hi, AUTOHIDE);
        else if (disabled_string(argv[1]))
	    HANDLE_CLEAR_FLAG(hi, AUTOHIDE);
	else {
            if (!(noreply))
	        reply("MSG_INVALID_BINARY", argv[1]);
	    return 0;
	}
    }

    if (!(noreply))
        reply("NSMSG_SET_AUTOHIDE", user_find_message(user, HANDLE_FLAGGED(hi, AUTOHIDE) ? "MSG_ON" : "MSG_OFF"));
    return 1;
}

static OPTION_FUNC(opt_style)
{
    char *style;

    if (argc > 1) {
        if (!irccasecmp(argv[1], "Clean"))
            hi->userlist_style = HI_STYLE_CLEAN;
        else if (!irccasecmp(argv[1], "Advanced"))
            hi->userlist_style = HI_STYLE_ADVANCED;
        else if (!irccasecmp(argv[1], "Classic"))
            hi->userlist_style = HI_STYLE_CLASSIC;
        else  /* Default to normal */
            hi->userlist_style = HI_STYLE_NORMAL;
    } /* TODO: give error if unknow style is chosen */

    switch (hi->userlist_style) {
        case HI_STYLE_ADVANCED:
            style = "Advanced";
            break;
        case HI_STYLE_CLASSIC:
            style = "Classic";
            break;
        case HI_STYLE_CLEAN:
            style = "Clean";
            break;
        case HI_STYLE_NORMAL:
        default:
        style = "Normal";
    }

    if (!(noreply))
        reply("NSMSG_SET_STYLE", style);
    return 1;
}

static OPTION_FUNC(opt_announcements)
{
    const char *choice;

    if (argc > 1) {
        if (enabled_string(argv[1]))
            hi->announcements = 'y';
        else if (disabled_string(argv[1]))
            hi->announcements = 'n';
        else if (!strcmp(argv[1], "?") || !irccasecmp(argv[1], "default"))
            hi->announcements = '?';
        else {
            if (!(noreply))
                reply("NSMSG_INVALID_ANNOUNCE", argv[1]);
            return 0;
        }
    }

    switch (hi->announcements) {
    case 'y': choice = user_find_message(user, "MSG_ON"); break;
    case 'n': choice = user_find_message(user, "MSG_OFF"); break;
    case '?': choice = "default"; break;
    default: choice = "unknown"; break;
    }
    if (!(noreply))
        reply("NSMSG_SET_ANNOUNCEMENTS", choice);
    return 1;
}

static OPTION_FUNC(opt_password)
{
    char crypted[MD5_CRYPT_LENGTH+1];
    if(argc < 2) {
       return 0;
    }
    if (!override) {
        if (!(noreply))
	    reply("NSMSG_USE_CMD_PASS");
	return 0;
    }

    cryptpass(argv[1], crypted);
#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
        int rc;
        if((rc = ldap_do_modify(hi->handle, crypted, NULL)) != LDAP_SUCCESS) {
             if (!(noreply))
                 reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
             return 0;
        }
    }
#endif
    strcpy(hi->passwd, crypted);
    if (nickserv_conf.sync_log)
        SyncLog("PASSCHANGE %s %s", hi->handle, hi->passwd);

    if (!(noreply))
        reply("NSMSG_SET_PASSWORD", "***");
    return 1;
}

static OPTION_FUNC(opt_flags)
{
    char flags[33];
    unsigned int ii, flen;

    if (!override) {
        if (!(noreply))
	    reply("MSG_SETTING_PRIVILEGED", argv[0]);
	return 0;
    }

    if (argc > 1)
	nickserv_apply_flags(user, hi, argv[1]);

    for (ii = flen = 0; handle_flags[ii]; ii++)
        if (hi->flags & (1 << ii))
            flags[flen++] = handle_flags[ii];
    flags[flen] = '\0';
    if (!(noreply)) {
        if (hi->flags)
            reply("NSMSG_SET_FLAGS", flags);
        else
            reply("NSMSG_SET_FLAGS", user_find_message(user, "MSG_NONE"));
    }
    return 1;
}

static OPTION_FUNC(opt_email)
{
    if (argc > 1) {
        const char *str;
        if (!valid_email(argv[1])) {
            if (!(noreply))
                reply("NSMSG_BAD_EMAIL_ADDR");
            return 0;
        }
        if ((str = mail_prohibited_address(argv[1]))) {
            if (!(noreply))
                reply("NSMSG_EMAIL_PROHIBITED", argv[1], str);
            return 0;
        }
        if (hi->email_addr && !irccasecmp(hi->email_addr, argv[1])) {
            if (!(noreply))
                reply("NSMSG_EMAIL_SAME");
        } else if (!override)
                nickserv_make_cookie(user, hi, EMAIL_CHANGE, argv[1], 0);
        else {
#ifdef WITH_LDAP
            if(nickserv_conf.ldap_enable && nickserv_conf.ldap_admin_dn) {
                int rc;
                if((rc = ldap_do_modify(hi->handle, NULL, argv[1])) != LDAP_SUCCESS) {
                   if (!(noreply))
                       reply("NSMSG_LDAP_FAIL", ldap_err2string(rc));
                   return 0;
                }
            }
#endif
            nickserv_set_email_addr(hi, argv[1]);
            if (hi->cookie)
                nickserv_eat_cookie(hi->cookie);
            if (!(noreply))
                reply("NSMSG_SET_EMAIL", visible_email_addr(user, hi));
        }
    } else {
        if (!(noreply))
            reply("NSMSG_SET_EMAIL", visible_email_addr(user, hi));
    }
    return 1;
}

static OPTION_FUNC(opt_maxlogins)
{
    unsigned char maxlogins;
    if (argc > 1) {
        maxlogins = strtoul(argv[1], NULL, 0);
        if ((maxlogins > nickserv_conf.hard_maxlogins) && !override) {
            if (!(noreply))
                reply("NSMSG_BAD_MAX_LOGINS", nickserv_conf.hard_maxlogins);
            return 0;
        }
        hi->maxlogins = maxlogins;
    }
    maxlogins = hi->maxlogins ? hi->maxlogins : nickserv_conf.default_maxlogins;
    if (!(noreply))
        reply("NSMSG_SET_MAXLOGINS", maxlogins);
    return 1;
}

static OPTION_FUNC(opt_advanced)
{
    if (argc > 1) {
	if (enabled_string(argv[1]))
	    HANDLE_SET_FLAG(hi, ADVANCED);
        else if (disabled_string(argv[1]))
	    HANDLE_CLEAR_FLAG(hi, ADVANCED);
	else {
            if (!(noreply))
	        reply("MSG_INVALID_BINARY", argv[1]);
	    return 0;
	}
    }

    if (!(noreply))
        reply("NSMSG_SET_ADVANCED", user_find_message(user, HANDLE_FLAGGED(hi, ADVANCED) ? "MSG_ON" : "MSG_OFF"));
    return 1;
}

static OPTION_FUNC(opt_language)
{
    struct language *lang;
    if (argc > 1) {
        lang = language_find(argv[1]);
        if (irccasecmp(lang->name, argv[1])) {
            if (!(noreply))
                reply("NSMSG_LANGUAGE_NOT_FOUND", argv[1], lang->name);
        }
        hi->language = lang;
    }
    if (!(noreply))
        reply("NSMSG_SET_LANGUAGE", hi->language->name);
    return 1;
}

static OPTION_FUNC(opt_karma)
{
    if (!override) {
        if (!(noreply))
            send_message(user, nickserv, "MSG_SETTING_PRIVILEGED", argv[0]);
        return 0;
    }

    if (argc > 1) {
        if (argv[1][0] == '+' && isdigit(argv[1][1])) {
            hi->karma += strtoul(argv[1] + 1, NULL, 10);
        } else if (argv[1][0] == '-' && isdigit(argv[1][1])) {
            hi->karma -= strtoul(argv[1] + 1, NULL, 10);
        } else {
            if (!(noreply))
                send_message(user, nickserv, "NSMSG_INVALID_KARMA", argv[1]);
        }
    }

    if (!(noreply))
        send_message(user, nickserv, "NSMSG_SET_KARMA", hi->karma);
    return 1;
}

/* Called from opserv from cmd_access */
int
oper_try_set_access(struct userNode *user, struct userNode *bot, struct handle_info *target, unsigned int new_level) {
    if (!oper_has_access(user, bot, nickserv_conf.modoper_level, 0))
        return 0;
    if ((user->handle_info->opserv_level < target->opserv_level)
        || ((user->handle_info->opserv_level == target->opserv_level)
            && (user->handle_info->opserv_level < 1000))) {
        send_message(user, bot, "MSG_USER_OUTRANKED", target->handle);
        return 0;
    }
    if ((user->handle_info->opserv_level < new_level)
        || ((user->handle_info->opserv_level == new_level)
            && (user->handle_info->opserv_level < 1000))) {
        send_message(user, bot, "NSMSG_OPSERV_LEVEL_BAD");
        return 0;
    }
    if (user->handle_info == target) {
        send_message(user, bot, "MSG_STUPID_ACCESS_CHANGE");
        return 0;
    }
#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable && *(nickserv_conf.ldap_oper_group_dn) && *(nickserv_conf.ldap_admin_dn)) {
        int rc;
        if(new_level > nickserv_conf.ldap_oper_group_level)
          rc = ldap_add2group(target->handle, nickserv_conf.ldap_oper_group_dn);
        else
          rc = ldap_delfromgroup(target->handle, nickserv_conf.ldap_oper_group_dn);
        if(rc != LDAP_SUCCESS && rc != LDAP_TYPE_OR_VALUE_EXISTS && rc != LDAP_NO_SUCH_ATTRIBUTE) {
           send_message(user, bot, "NSMSG_LDAP_FAIL", ldap_err2string(rc));
           return 0;
        }
    }
    if(nickserv_conf.ldap_enable && *(nickserv_conf.ldap_field_oslevel) && *(nickserv_conf.ldap_admin_dn)) {
      int rc;
      if((rc = ldap_do_oslevel(target->handle, new_level, target->opserv_level)) != LDAP_SUCCESS) {
        send_message(user, bot, "NSMSG_LDAP_FAIL", ldap_err2string(rc));
        return 0;
      }
    }
#endif
    if (target->opserv_level == new_level)
        return 0;
    log_module(NS_LOG, LOG_INFO, "Account %s setting oper level for account %s to %d (from %d).",
        user->handle_info->handle, target->handle, new_level, target->opserv_level);
    target->opserv_level = new_level;
    return 1;
}

static OPTION_FUNC(opt_level)
{
    int res;

    if (!override) {
        if (!(noreply))
	    reply("MSG_SETTING_PRIVILEGED", argv[0]);
	return 0;
    }

    res = (argc > 1) ? oper_try_set_access(user, nickserv, hi, strtoul(argv[1], NULL, 0)) : 0;
    if (!(noreply))
        reply("NSMSG_SET_LEVEL", hi->opserv_level);
    return res;
}

static OPTION_FUNC(opt_epithet)
{
    if ((argc > 1) && oper_has_access(user, nickserv, nickserv_conf.set_epithet_level, 0)) {
        char *epithet;
        struct userNode *target, *next_un;

        if (!override) {
            if (!(noreply))
                reply("MSG_SETTING_PRIVILEGED", argv[0]);
            return 0;
        }

        epithet = unsplit_string(argv+1, argc-1, NULL);

        if (hi->epithet)
            free(hi->epithet);
        if ((epithet[0] == '*') && !epithet[1])
            hi->epithet = NULL;
        else
            hi->epithet = strdup(epithet);

        for (target = hi->users; target; target = next_un) {
          irc_swhois(nickserv, target, hi->epithet);

          next_un = target->next_authed;
        }
    }

    if (!(noreply)) {
        if (hi->epithet)
            reply("NSMSG_SET_EPITHET", hi->epithet);
        else
            reply("NSMSG_SET_EPITHET", user_find_message(user, "MSG_NONE"));
    }
    return 1;
}

static OPTION_FUNC(opt_title)
{
    char *title;
    const char *none = NULL;
    char *sptr;

    if ((argc > 1) && oper_has_access(user, nickserv, nickserv_conf.set_title_level, 0)) {
        if (!override) {
            if (!(noreply))
                reply("MSG_SETTING_PRIVILEGED", argv[0]);
            return 0;
        }

        title = argv[1];
        if(!strcmp(title, "*")) {
            free(hi->fakehost);
            hi->fakehost = NULL;
        }
        else {
            if (strchr(title, '.')) {
                if (!(noreply))
                    reply("NSMSG_TITLE_INVALID");
                return 0;
            }
            /* Alphanumeric titles only. */
            for(sptr = title; *sptr; sptr++) {
                if(!isalnum(*sptr) && *sptr != '-') {
                    if (!(noreply))
                        reply("NSMSG_TITLE_INVALID");
                    return 0;
                }
            }
            if ((strlen(user->handle_info->handle) + strlen(title) +
                 strlen(nickserv_conf.titlehost_suffix) + 2) > HOSTLEN) {
                if (!(noreply))
                    reply("NSMSG_TITLE_TRUNCATED");
                return 0;
            }
            free(hi->fakehost);
            hi->fakehost = malloc(strlen(title)+2);
            hi->fakehost[0] = '.';
            strcpy(hi->fakehost+1, title);
        }
        apply_fakehost(hi);
    } else if (hi->fakehost && (hi->fakehost[0] == '.'))
        title = hi->fakehost + 1;
    else {
        /* If theres no title set then the default title will therefore
           be the first part of hidden_host in x3.conf, so for
           consistency with opt_fakehost we will print this here.
           This isnt actually used in P10, its just handled to keep from crashing... */
        char *hs, *hidden_suffix, *rest;

        hs = conf_get_data("server/hidden_host", RECDB_QSTRING);
        hidden_suffix = strdup(hs);

        /* Yes we do this twice */
        if((rest = strchr(hidden_suffix, '.')))
        {
            *rest = '\0';
            title = hidden_suffix;
        }
        else
        {
            /* A lame default if someone configured hidden_host to something lame */
            title = strdup("users");
            free(hidden_suffix);
        }

    }

    if (!title)
        none = user_find_message(user, "MSG_NONE");
    if (!(noreply))
        send_message(user, nickserv, "NSMSG_SET_TITLE", title ? title : none);
    return 1;
}

int 
check_vhost(char *vhost, struct userNode *user, struct svccmd *cmd) 
{
    unsigned int y;

    // check for a dot in the vhost
    if(strchr(vhost, '.') == NULL) {
        reply("NSMSG_NOT_VALID_FAKEHOST_DOT", vhost);
        return 0;  
    }

    // check for a @ in the vhost
    if(strchr(vhost, '@') != NULL) {
        reply("NSMSG_NOT_VALID_FAKEHOST_AT", vhost);
        return 0;  
    }

    // check for denied words, inspired by monk at paki.sex
    for(y = 0; y < nickserv_conf.denied_fakehost_words->used; y++) {
        if(strstr(vhost, nickserv_conf.denied_fakehost_words->list[y]) != NULL) {
            reply("NSMSG_DENIED_FAKEHOST_WORD", vhost, nickserv_conf.denied_fakehost_words->list[y]);
            return 0;
        }
    } 

   // check for ircu's HOSTLEN length.
   if(strlen(vhost) >= HOSTLEN) {
       reply("NSMSG_NOT_VALID_FAKEHOST_LEN", vhost);
       return 0;
   }

   /* This can be handled by the regex now if desired.
   if (vhost[strspn(vhost, "0123456789.")]) {
       hostname = vhost + strlen(vhost);
       for (depth = 1; depth && (hostname > vhost); depth--) {
           hostname--;
           while ((hostname > vhost) && (*hostname != '.')) hostname--;
       }

       if (*hostname == '.') hostname++; * advance past last dot we saw *
       if(strlen(hostname) > 4) {
           reply("NSMSG_NOT_VALID_FAKEHOST_TLD_LEN", vhost);
           return 0;
       }
   }
   */
   /* test either regex or as valid handle */
   if (nickserv_conf.valid_fakehost_regex_set) {
       int err = regexec(&nickserv_conf.valid_fakehost_regex, vhost, 0, 0, 0);
       if (err) {
           char buff[256];
           buff[regerror(err, &nickserv_conf.valid_fakehost_regex, buff, sizeof(buff))] = 0;
           log_module(NS_LOG, LOG_INFO, "regexec error: %s (%d)", buff, err);
       }
       if(err == REG_NOMATCH) {
           reply("NSMSG_NOT_VALID_FAKEHOST_REGEX", vhost);
           return 0;
       }
   }


   return 1;
}

static OPTION_FUNC(opt_fakehost)
{
    const char *fake;

    if ((argc > 1) && oper_has_access(user, nickserv, nickserv_conf.set_fakehost_level, 0)) {
        if (!override) {
            if (!(noreply))
                reply("MSG_SETTING_PRIVILEGED", argv[0]);
            return 0;
        }

        fake = argv[1];
        if ((strlen(fake) > HOSTLEN) || (fake[0] == '.')) {
            if (!(noreply))
                reply("NSMSG_FAKEHOST_INVALID", HOSTLEN);
            return 0;
        }
        if (!strcmp(fake, "*")) {
            if(hi->fakehost) {
                free(hi->fakehost);
                hi->fakehost = NULL;
            }
        } 
        else if (!check_vhost(argv[1], user, cmd))  {
            /* check_vhost takes care of error reply */
            return 0;
        }
        else {
            if(hi->fakehost)
                free(hi->fakehost);
            hi->fakehost = strdup(fake);
        }
        apply_fakehost(hi);
        fake = hi->fakehost;
    } else
        fake = generate_fakehost(hi);

    /* Tell them we set the host */
    if (!fake)
        fake = user_find_message(user, "MSG_NONE");
    if (!(noreply))
        reply("NSMSG_SET_FAKEHOST", fake);
    return 1;
}

static OPTION_FUNC(opt_note)
{
    if (!override) {
        if (!(noreply))
            reply("MSG_SETTING_PRIVILEGED", argv[0]);
        return 0;
    }

    if (argc > 1) {
        char *text = unsplit_string(argv + 1, argc - 1, NULL);

        if (hi->note)
            free(hi->note);

        if ((text[0] == '*') && !text[1])
            hi->note = NULL;
        else {
            if (!(hi->note = nickserv_add_note(user->handle_info->handle, now, text)))
                hi->note = NULL;
        }
    }

    if (!(noreply))
        reply("NSMSG_SET_NOTE", hi->note ? hi->note->note : user_find_message(user, "MSG_NONE"));
    return 1;
}

static NICKSERV_FUNC(cmd_reclaim)
{
    struct nick_info *ni;
    struct userNode *victim;

    NICKSERV_MIN_PARMS(2);
    ni = dict_find(nickserv_nick_dict, argv[1], 0);
    if (!ni) {
        reply("NSMSG_UNKNOWN_NICK", argv[1]);
        return 0;
    }
    if (ni->owner != user->handle_info) {
        reply("NSMSG_NOT_YOUR_NICK", ni->nick);
        return 0;
    }
    victim = GetUserH(ni->nick);
    if (!victim) {
        reply("MSG_NICK_UNKNOWN", ni->nick);
        return 0;
    }
    if (victim == user) {
        reply("NSMSG_NICK_USER_YOU");
        return 0;
    }
    nickserv_reclaim(victim, ni, nickserv_conf.reclaim_action);
    switch (nickserv_conf.reclaim_action) {
    case RECLAIM_NONE: reply("NSMSG_RECLAIMED_NONE"); break;
    case RECLAIM_WARN: reply("NSMSG_RECLAIMED_WARN", victim->nick); break;
    case RECLAIM_SVSNICK: reply("NSMSG_RECLAIMED_SVSNICK", victim->nick); break;
    case RECLAIM_KILL: reply("NSMSG_RECLAIMED_KILL", victim->nick); break;
    }
    return 1;
}

static NICKSERV_FUNC(cmd_unregnick)
{
    const char *nick;
    struct handle_info *hi;
    struct nick_info *ni;

    hi = user->handle_info;
    nick = (argc < 2) ? user->nick : (const char*)argv[1];
    ni = dict_find(nickserv_nick_dict, nick, NULL);
    if (!ni) {
	reply("NSMSG_UNKNOWN_NICK", nick);
	return 0;
    }
    if (hi != ni->owner) {
	reply("NSMSG_NOT_YOUR_NICK", nick);
	return 0;
    }
    reply("NSMSG_UNREGNICK_SUCCESS", ni->nick);
    delete_nick(ni);
    return 1;
}

static NICKSERV_FUNC(cmd_ounregnick)
{
    struct nick_info *ni;

    NICKSERV_MIN_PARMS(2);
    if (!(ni = get_nick_info(argv[1]))) {
	reply("NSMSG_NICK_NOT_REGISTERED", argv[1]);
	return 0;
    }
    if (!oper_outranks(user, ni->owner))
        return 0;
    reply("NSMSG_UNREGNICK_SUCCESS", ni->nick);
    delete_nick(ni);
    return 1;
}

static NICKSERV_FUNC(cmd_unregister)
{
    struct handle_info *hi;
    char *passwd;

    NICKSERV_MIN_PARMS(2);
    hi = user->handle_info;
    passwd = argv[1];
    argv[1] = "****";
    if (checkpass(passwd, hi->passwd)) {
        if(nickserv_unregister_handle(hi, user, cmd->parent->bot))
            return 1;
        else
            return 0;
    } else {
	log_module(NS_LOG, LOG_INFO, "Account '%s' tried to unregister with the wrong password.", hi->handle);
	reply("NSMSG_PASSWORD_INVALID");
        return 0;
    }
}

static NICKSERV_FUNC(cmd_ounregister)
{
    struct handle_info *hi;
    char reason[MAXLEN];
    int force;

    NICKSERV_MIN_PARMS(2);
    if (!(hi = get_victim_oper(user, argv[1])))
        return 0;

    if (HANDLE_FLAGGED(hi, NODELETE)) {
        reply("NSMSG_UNREGISTER_NODELETE", hi->handle);
        return 0;
    }

    force = IsOper(user) && (argc > 2) && !irccasecmp(argv[2], "force");
    if (!force &&
        ((hi->flags & nickserv_conf.ounregister_flags)
         || hi->users
         || (hi->last_quit_host[0] && ((unsigned)(now - hi->lastseen) < nickserv_conf.ounregister_inactive)))) {
        reply((IsOper(user) ? "NSMSG_UNREGISTER_MUST_FORCE" : "NSMSG_UNREGISTER_CANNOT_FORCE"), hi->handle);
        return 0;
    }
    snprintf(reason, sizeof(reason), "%s unregistered account %s.", user->handle_info->handle, hi->handle);
    global_message(MESSAGE_RECIPIENT_STAFF, reason);
    if(nickserv_unregister_handle(hi, user, cmd->parent->bot))
        return 1;
    else
        return 0;
}

static NICKSERV_FUNC(cmd_status)
{
    if (nickserv_conf.disable_nicks) {
        reply("NSMSG_GLOBAL_STATS_NONICK",
                        dict_size(nickserv_handle_dict));
    } else {
        if (user->handle_info) {
            int cnt=0;
            struct nick_info *ni;
            for (ni=user->handle_info->nicks; ni; ni=ni->next) cnt++;
            reply("NSMSG_HANDLE_STATS", cnt);
        } else {
            reply("NSMSG_HANDLE_NONE");
        }
        reply("NSMSG_GLOBAL_STATS",
              dict_size(nickserv_handle_dict),
              dict_size(nickserv_nick_dict));
    }
    return 1;
}

static NICKSERV_FUNC(cmd_ghost)
{
    struct userNode *target;
    char reason[MAXLEN];

    NICKSERV_MIN_PARMS(2);
    if (!(target = GetUserH(argv[1]))) {
        reply("MSG_NICK_UNKNOWN", argv[1]);
        return 0;
    }
    if (target == user) {
        reply("NSMSG_CANNOT_GHOST_SELF");
        return 0;
    }
    if (!target->handle_info || (target->handle_info != user->handle_info)) {
        reply("NSMSG_CANNOT_GHOST_USER", target->nick);
        return 0;
    }
    snprintf(reason, sizeof(reason), "Ghost kill on account %s (requested by %s).", target->handle_info->handle, user->nick);
    DelUser(target, nickserv, 1, reason);
    reply("NSMSG_GHOST_KILLED", argv[1]);
    return 1;
}

static NICKSERV_FUNC(cmd_vacation)
{
    HANDLE_SET_FLAG(user->handle_info, FROZEN);
    reply("NSMSG_ON_VACATION");
    return 1;
}

static int
nickserv_saxdb_write(struct saxdb_context *ctx) {
    dict_iterator_t it;
    struct handle_info *hi;
    char flags[33];

    for (it = dict_first(nickserv_handle_dict); it; it = iter_next(it)) {
        hi = iter_data(it);
        saxdb_start_record(ctx, iter_key(it), 0);
        if (hi->announcements != '?') {
            flags[0] = hi->announcements;
            flags[1] = 0;
            saxdb_write_string(ctx, KEY_ANNOUNCEMENTS, flags);
        }
        if (hi->cookie) {
            struct handle_cookie *cookie = hi->cookie;
            char *type;

            switch (cookie->type) {
            case ACTIVATION: type = KEY_ACTIVATION; break;
            case PASSWORD_CHANGE: type = KEY_PASSWORD_CHANGE; break;
            case EMAIL_CHANGE: type = KEY_EMAIL_CHANGE; break;
            case ALLOWAUTH: type = KEY_ALLOWAUTH; break;
            default: type = NULL; break;
            }
            if (type) {
                saxdb_start_record(ctx, KEY_COOKIE, 0);
                saxdb_write_string(ctx, KEY_COOKIE_TYPE, type);
                saxdb_write_int(ctx, KEY_COOKIE_EXPIRES, cookie->expires);
                if (cookie->data)
                    saxdb_write_string(ctx, KEY_COOKIE_DATA, cookie->data);
                saxdb_write_string(ctx, KEY_COOKIE, cookie->cookie);
                saxdb_end_record(ctx);
            }
        }
        if (hi->email_addr)
            saxdb_write_string(ctx, KEY_EMAIL_ADDR, hi->email_addr);
        if (hi->epithet)
            saxdb_write_string(ctx, KEY_EPITHET, hi->epithet);
        if (hi->note) {
            saxdb_start_record(ctx, KEY_NOTE_NOTE, 0);
            saxdb_write_string(ctx, KEY_NOTE_SETTER, hi->note->setter);
            saxdb_write_int(ctx, KEY_NOTE_DATE, hi->note->date);
            saxdb_write_string(ctx, KEY_NOTE_NOTE, hi->note->note);
            saxdb_end_record(ctx);
        }

        if (hi->fakehost)
            saxdb_write_string(ctx, KEY_FAKEHOST, hi->fakehost);
        if (hi->flags) {
            int ii, flen;

            for (ii=flen=0; handle_flags[ii]; ++ii)
                if (hi->flags & (1 << ii))
                    flags[flen++] = handle_flags[ii];
            flags[flen] = 0;
            saxdb_write_string(ctx, KEY_FLAGS, flags);
        }
        if (hi->infoline)
            saxdb_write_string(ctx, KEY_INFO, hi->infoline);
        if (hi->last_quit_host[0])
            saxdb_write_string(ctx, KEY_LAST_QUIT_HOST, hi->last_quit_host);
        saxdb_write_int(ctx, KEY_LAST_SEEN, hi->lastseen);
        if (hi->karma != 0)
            saxdb_write_sint(ctx, KEY_KARMA, hi->karma);
        if (hi->masks->used)
            saxdb_write_string_list(ctx, KEY_MASKS, hi->masks);
        if (hi->sslfps->used)
            saxdb_write_string_list(ctx, KEY_SSLFPS, hi->sslfps);
        if (hi->ignores->used)
            saxdb_write_string_list(ctx, KEY_IGNORES, hi->ignores);
        if (hi->maxlogins)
            saxdb_write_int(ctx, KEY_MAXLOGINS, hi->maxlogins);
        if (hi->nicks) {
            struct nick_info *ni;

            saxdb_start_record(ctx, KEY_NICKS_EX, 0);
            for (ni = hi->nicks; ni; ni = ni->next) {
                saxdb_start_record(ctx, ni->nick, 0);
                saxdb_write_int(ctx, KEY_REGISTER_ON, ni->registered);
                saxdb_write_int(ctx, KEY_LAST_SEEN, ni->lastseen);
                saxdb_end_record(ctx);
            }
            saxdb_end_record(ctx);
        }
        if (hi->opserv_level)
            saxdb_write_int(ctx, KEY_OPSERV_LEVEL, hi->opserv_level);
        if (hi->language != lang_C)
            saxdb_write_string(ctx, KEY_LANGUAGE, hi->language->name);
        saxdb_write_string(ctx, KEY_PASSWD, hi->passwd);
        saxdb_write_int(ctx, KEY_REGISTER_ON, hi->registered);
        if (hi->screen_width)
            saxdb_write_int(ctx, KEY_SCREEN_WIDTH, hi->screen_width);
        if (hi->table_width)
            saxdb_write_int(ctx, KEY_TABLE_WIDTH, hi->table_width);
        flags[0] = hi->userlist_style;
        flags[1] = 0;
        saxdb_write_string(ctx, KEY_USERLIST_STYLE, flags);
        saxdb_end_record(ctx);
    }

    return 0;
}

static handle_merge_func_t *handle_merge_func_list;
static void **handle_merge_func_list_extra;
static unsigned int handle_merge_func_size = 0, handle_merge_func_used = 0;

void
reg_handle_merge_func(handle_merge_func_t func, void *extra)
{
    if (handle_merge_func_used == handle_merge_func_size) {
        if (handle_merge_func_size) {
            handle_merge_func_size <<= 1;
            handle_merge_func_list = realloc(handle_merge_func_list, handle_merge_func_size*sizeof(handle_merge_func_t));
            handle_merge_func_list_extra = realloc(handle_merge_func_list_extra, handle_merge_func_size*sizeof(void*));
        } else {
            handle_merge_func_size = 8;
            handle_merge_func_list = malloc(handle_merge_func_size*sizeof(handle_merge_func_t));
            handle_merge_func_list_extra = malloc(handle_merge_func_size*sizeof(void*));
        }
    }
    handle_merge_func_list[handle_merge_func_used] = func;
    handle_merge_func_list_extra[handle_merge_func_used++] = extra;
}

static NICKSERV_FUNC(cmd_merge)
{
    struct handle_info *hi_from, *hi_to;
    struct userNode *last_user;
    struct userData *cList, *cListNext;
    unsigned int ii, jj, n;

    NICKSERV_MIN_PARMS(3);

    if (!(hi_from = get_victim_oper(user, argv[1])))
        return 0;
    if (!(hi_to = get_victim_oper(user, argv[2])))
        return 0;
    if (hi_to == hi_from) {
        reply("NSMSG_CANNOT_MERGE_SELF", hi_to->handle);
        return 0;
    }

    for (n=0; n<handle_merge_func_used; n++)
        handle_merge_func_list[n](user, hi_to, hi_from, handle_merge_func_list_extra[n]);

    /* Append "from" handle's nicks to "to" handle's nick list. */
    if (hi_to->nicks) {
        struct nick_info *last_ni;
        for (last_ni=hi_to->nicks; last_ni->next; last_ni=last_ni->next) ;
        last_ni->next = hi_from->nicks;
    }
    while (hi_from->nicks) {
        hi_from->nicks->owner = hi_to;
        hi_from->nicks = hi_from->nicks->next;
    }

    /* Merge the hostmasks. */
    for (ii=0; ii<hi_from->masks->used; ii++) {
        char *mask = hi_from->masks->list[ii];
        for (jj=0; jj<hi_to->masks->used; jj++)
            if (match_ircglobs(hi_to->masks->list[jj], mask))
                break;
        if (jj==hi_to->masks->used) /* Nothing from the "to" handle covered this mask, so add it. */
            string_list_append(hi_to->masks, strdup(mask));
    }

    /* Merge the SSL fingerprints. */
    for (ii=0; ii<hi_from->sslfps->used; ii++) {
        char *sslfp = hi_from->sslfps->list[ii];
        for (jj=0; jj<hi_to->sslfps->used; jj++)
            if (!irccasecmp(hi_to->sslfps->list[jj], sslfp))
                break;
        if (jj==hi_to->sslfps->used) /* Nothing from the "to" handle covered this sslfp, so add it. */
            string_list_append(hi_to->sslfps, strdup(sslfp));
    }

    /* Merge the ignores. */
    for (ii=0; ii<hi_from->ignores->used; ii++) {
        char *ignore = hi_from->ignores->list[ii];
        for (jj=0; jj<hi_to->ignores->used; jj++)
            if (match_ircglobs(hi_to->ignores->list[jj], ignore))
                break;
        if (jj==hi_to->ignores->used) /* Nothing from the "to" handle covered this mask, so add it. */
            string_list_append(hi_to->ignores, strdup(ignore));
    }

    /* Merge the lists of authed users. */
    if (hi_to->users) {
        for (last_user=hi_to->users; last_user->next_authed; last_user=last_user->next_authed) ;
        last_user->next_authed = hi_from->users;
    } else {
        hi_to->users = hi_from->users;
    }
    /* Repoint the old "from" handle's users. */
    for (last_user=hi_from->users; last_user; last_user=last_user->next_authed) {
        last_user->handle_info = hi_to;
    }
    hi_from->users = NULL;

    /* Merge channel userlists. */
    for (cList=hi_from->channels; cList; cList=cListNext) {
        struct userData *cList2;
        cListNext = cList->u_next;
        for (cList2=hi_to->channels; cList2; cList2=cList2->u_next)
            if (cList->channel == cList2->channel)
                break;
        if (cList2 && (cList2->access >= cList->access)) {
            log_module(NS_LOG, LOG_INFO, "Merge: %s had only %d access in %s (versus %d for %s)", hi_from->handle, cList->access, cList->channel->channel->name, cList2->access, hi_to->handle);
            /* keep cList2 in hi_to; remove cList from hi_from */
            del_channel_user(cList, 1);
        } else {
            if (cList2) {
                log_module(NS_LOG, LOG_INFO, "Merge: %s had only %d access in %s (versus %d for %s)", hi_to->handle, cList2->access, cList->channel->channel->name, cList->access, hi_from->handle);
                /* remove the lower-ranking cList2 from hi_to */
                del_channel_user(cList2, 1);
            } else {
                log_module(NS_LOG, LOG_INFO, "Merge: %s had no access in %s", hi_to->handle, cList->channel->channel->name);
            }
            /* cList needs to be moved from hi_from to hi_to */
            cList->handle = hi_to;
            /* Remove from linked list for hi_from */
            assert(!cList->u_prev);
            hi_from->channels = cList->u_next;
            if (cList->u_next)
                cList->u_next->u_prev = cList->u_prev;
            /* Add to linked list for hi_to */
            cList->u_prev = NULL;
            cList->u_next = hi_to->channels;
            if (hi_to->channels)
                hi_to->channels->u_prev = cList;
            hi_to->channels = cList;
        }
    }

    /* Do they get an OpServ level promotion? */
    if (hi_from->opserv_level > hi_to->opserv_level)
        hi_to->opserv_level = hi_from->opserv_level;

    /* What about last seen time? */
    if (hi_from->lastseen > hi_to->lastseen)
        hi_to->lastseen = hi_from->lastseen;

    /* New karma is the sum of the two original karmas. */
    hi_to->karma += hi_from->karma;

    /* Does a fakehost carry over?  (This intentionally doesn't set it
     * for users previously attached to hi_to.  They'll just have to
     * reconnect.)
     */
    if (hi_from->fakehost && !hi_to->fakehost)
        hi_to->fakehost = strdup(hi_from->fakehost);

    /* Notify of success. */
    reply("NSMSG_HANDLES_MERGED", hi_from->handle, hi_to->handle);
    global_message_args(MESSAGE_RECIPIENT_OPERS, "NSMSG_ACCOUNT_MERGED", user->nick,
                        user->handle_info->handle, hi_from->handle, hi_to->handle);

    /* Unregister the "from" handle. */
    nickserv_unregister_handle(hi_from, NULL, cmd->parent->bot);
    /* TODO: fix it so that if the ldap delete in nickserv_unregister_handle fails, 
     * the process isn't completed.
     */

    return 1;
}

struct nickserv_discrim {
    unsigned long flags_on, flags_off;
    time_t min_registered, max_registered;
    time_t lastseen;
    unsigned int limit;
    int min_level, max_level;
    int min_karma, max_karma;
    enum { SUBSET, EXACT, SUPERSET, LASTQUIT } hostmask_type;
    const char *nickmask;
    const char *hostmask;
    const char *handlemask;
    const char *emailmask;
    const char *titlemask;
    const char *setwhat;
    const char *setval;
    struct svccmd *cmd;
#ifdef WITH_LDAP
    unsigned int inldap;
#endif
};

typedef void (*discrim_search_func)(struct userNode *source, struct handle_info *hi, struct nickserv_discrim *discrim);

struct discrim_apply_info {
    struct nickserv_discrim *discrim;
    discrim_search_func func;
    struct userNode *source;
    unsigned int matched;
};

static struct nickserv_discrim *
nickserv_discrim_create(struct svccmd *cmd, struct userNode *user, unsigned int argc, char *argv[])
{
    unsigned int i;
    struct nickserv_discrim *discrim;

    discrim = malloc(sizeof(*discrim));
    memset(discrim, 0, sizeof(*discrim));
    discrim->min_level = 0;
    discrim->max_level = INT_MAX;
    discrim->limit = 50;
    discrim->min_registered = 0;
    discrim->max_registered = INT_MAX;
    discrim->lastseen = LONG_MAX;
    discrim->min_karma = INT_MIN;
    discrim->max_karma = INT_MAX;
    discrim->cmd = cmd;
#ifdef WITH_LDAP
    discrim->inldap = 2;
#endif

    for (i=0; i<argc; i++) {
        if (i == argc - 1) {
            reply("MSG_MISSING_PARAMS", argv[i]);
            goto fail;
        }
        if (!irccasecmp(argv[i], "limit")) {
            discrim->limit = strtoul(argv[++i], NULL, 0);
        } else if (!irccasecmp(argv[i], "flags")) {
            nickserv_modify_handle_flags(user, nickserv, argv[++i], &discrim->flags_on, &discrim->flags_off);
        } else if (!irccasecmp(argv[i], "registered")) {
            const char *cmp = argv[++i];
            if (cmp[0] == '<') {
                if (cmp[1] == '=') {
                    discrim->min_registered = now - ParseInterval(cmp+2);
                } else {
                    discrim->min_registered = now - ParseInterval(cmp+1) + 1;
                }
            } else if (cmp[0] == '=') {
                discrim->min_registered = discrim->max_registered = now - ParseInterval(cmp+1);
            } else if (cmp[0] == '>') {
                if (cmp[1] == '=') {
                    discrim->max_registered = now - ParseInterval(cmp+2);
                } else {
                    discrim->max_registered = now - ParseInterval(cmp+1) - 1;
                }
            } else {
                reply("MSG_INVALID_CRITERIA", cmp);
            }
        } else if (!irccasecmp(argv[i], "seen")) {
            discrim->lastseen = now - ParseInterval(argv[++i]);
        } else if (!nickserv_conf.disable_nicks && !irccasecmp(argv[i], "nickmask")) {
            discrim->nickmask = argv[++i];
        } else if (!irccasecmp(argv[i], "setwhat")) {
            discrim->setwhat = argv[++i];
            if (!(dict_find(nickserv_opt_dict, discrim->setwhat, NULL))) {
                reply("NSMSG_INVALID_OPTION", discrim->setwhat);
                goto fail;
            }
        } else if (!irccasecmp(argv[i], "setvalue")) {
            discrim->setval = argv[++i];
        } else if (!irccasecmp(argv[i], "hostmask")) {
            i++;
            if (!irccasecmp(argv[i], "exact")) {
                if (i == argc - 1) {
                    reply("MSG_MISSING_PARAMS", argv[i]);
                    goto fail;
                }
                discrim->hostmask_type = EXACT;
            } else if (!irccasecmp(argv[i], "subset")) {
                if (i == argc - 1) {
                    reply("MSG_MISSING_PARAMS", argv[i]);
                    goto fail;
                }
                discrim->hostmask_type = SUBSET;
            } else if (!irccasecmp(argv[i], "superset")) {
                if (i == argc - 1) {
                    reply("MSG_MISSING_PARAMS", argv[i]);
                    goto fail;
                }
                discrim->hostmask_type = SUPERSET;
	    } else if (!irccasecmp(argv[i], "lastquit") || !irccasecmp(argv[i], "lastauth")) {
	       if (i == argc - 1) {
	           reply("MSG_MISSING_PARAMS", argv[i]);
		   goto fail;
	       }
	       discrim->hostmask_type = LASTQUIT;
            } else {
                i--;
                discrim->hostmask_type = SUPERSET;
            }
            discrim->hostmask = argv[++i];
        } else if (!irccasecmp(argv[i], "handlemask") || !irccasecmp(argv[i], "accountmask") || !irccasecmp(argv[i], "account")) {
            if (!irccasecmp(argv[++i], "*")) {
                discrim->handlemask = 0;
            } else {
                discrim->handlemask = argv[i];
            }
        } else if (!irccasecmp(argv[i], "email")) {
            if (user->handle_info->opserv_level < nickserv_conf.email_search_level) {
                reply("MSG_NO_SEARCH_ACCESS", "email");
                goto fail;
            } else if (!irccasecmp(argv[++i], "*")) {
                discrim->emailmask = 0;
            } else {
                discrim->emailmask = argv[i];
            }
        } else if (!irccasecmp(argv[i], "title")) {
            if (!irccasecmp(argv[++i], "*")) {
                discrim->titlemask = 0;
            } else {
                discrim->titlemask = argv[i];
            }
        } else if (!irccasecmp(argv[i], "access")) {
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
                reply("MSG_INVALID_CRITERIA", cmp);
            }
        } else if (!irccasecmp(argv[i], "karma")) {
            const char *cmp = argv[++i];
            if (cmp[0] == '<') {
                if (cmp[1] == '=') {
                    discrim->max_karma = strtoul(cmp+2, NULL, 0);
                } else {
                    discrim->max_karma = strtoul(cmp+1, NULL, 0) - 1;
                }
            } else if (cmp[0] == '=') {
                discrim->min_karma = discrim->max_karma = strtoul(cmp+1, NULL, 0);
            } else if (cmp[0] == '>') {
                if (cmp[1] == '=') {
                    discrim->min_karma = strtoul(cmp+2, NULL, 0);
                } else {
                    discrim->min_karma = strtoul(cmp+1, NULL, 0) + 1;
                }
            } else {
                send_message(user, nickserv, "MSG_INVALID_CRITERIA", cmp);
            }
#ifdef WITH_LDAP
        } else if (nickserv_conf.ldap_enable && !irccasecmp(argv[i], "inldap")) {
          i++;
          if(true_string(argv[i])) {
             discrim->inldap = 1;
          }
          else if (false_string(argv[i])) {
             discrim->inldap = 0;
          }
          else {
            reply("MSG_INVALID_BINARY", argv[i]);
          }
#endif
        } else { 
            reply("MSG_INVALID_CRITERIA", argv[i]);
            goto fail;
        }
    }
    return discrim;
  fail:
    free(discrim);
    return NULL;
}

static int
nickserv_discrim_match(struct nickserv_discrim *discrim, struct handle_info *hi)
{
    char *title = NULL;

    if (hi->fakehost && (hi->fakehost[0] == '.'))
      title = hi->fakehost + 1;

    if (((discrim->flags_on & hi->flags) != discrim->flags_on)
        || (discrim->flags_off & hi->flags)
        || (discrim->min_registered > hi->registered)
        || (discrim->max_registered < hi->registered)
        || (discrim->lastseen < (hi->users?now:hi->lastseen))
        || (discrim->handlemask && !match_ircglob(hi->handle, discrim->handlemask))
        || (discrim->emailmask && (!hi->email_addr || !match_ircglob(hi->email_addr, discrim->emailmask)))
        || (discrim->titlemask && (!title || !match_ircglob(title, discrim->titlemask)))
        || (discrim->min_level > hi->opserv_level)
        || (discrim->max_level < hi->opserv_level)
        || (discrim->min_karma > hi->karma)
        || (discrim->max_karma < hi->karma)
        ) {
        return 0;
    }
    if (discrim->hostmask) {
        unsigned int i;
        for (i=0; i<hi->masks->used; i++) {
            const char *mask = hi->masks->list[i];
            if ((discrim->hostmask_type == SUBSET)
                && (match_ircglobs(discrim->hostmask, mask))) break;
            else if ((discrim->hostmask_type == EXACT)
                     && !irccasecmp(discrim->hostmask, mask)) break;
            else if ((discrim->hostmask_type == SUPERSET)
                     && (match_ircglobs(mask, discrim->hostmask))) break;
	    else if ((discrim->hostmask_type == LASTQUIT)
	    	     && (match_ircglobs(discrim->hostmask, hi->last_quit_host))) break;
        }
        if (i==hi->masks->used) return 0;
    }
    if (discrim->nickmask) {
        struct nick_info *nick = hi->nicks;
        while (nick) {
            if (match_ircglob(nick->nick, discrim->nickmask)) break;
            nick = nick->next;
        }
        if (!nick) return 0;
    }
#ifdef WITH_LDAP
    if(nickserv_conf.ldap_enable && discrim->inldap != 2) {
        int rc;
        rc = ldap_get_user_info(hi->handle, NULL);
        if(discrim->inldap == 1 && rc != LDAP_SUCCESS)
           return 0;
        if(discrim->inldap == 0 && rc == LDAP_SUCCESS)
           return 0;
    }

#endif
    return 1;
}

static unsigned int
nickserv_discrim_search(struct nickserv_discrim *discrim, discrim_search_func dsf, struct userNode *source)
{
    dict_iterator_t it, next;
    unsigned int matched;

    for (it = dict_first(nickserv_handle_dict), matched = 0;
         it && (matched < discrim->limit);
         it = next) {
        next = iter_next(it);
        if (nickserv_discrim_match(discrim, iter_data(it))) {
            dsf(source, iter_data(it), discrim);
            matched++;
        }
    }
    return matched;
}

static void
search_print_func(struct userNode *source, struct handle_info *match, UNUSED_ARG(struct nickserv_discrim *discrim))
{
    send_message(source, nickserv, "NSMSG_SEARCH_MATCH", match->handle);
}

static void
search_count_func(UNUSED_ARG(struct userNode *source), UNUSED_ARG(struct handle_info *match), UNUSED_ARG(struct nickserv_discrim *discrim))
{
}

static void
search_unregister_func (struct userNode *source, struct handle_info *match, UNUSED_ARG(struct nickserv_discrim *discrim))
{
    if (oper_has_access(source, nickserv, match->opserv_level, 0))
        nickserv_unregister_handle(match, source, nickserv); // XXX nickserv hard coded
}

#ifdef WITH_LDAP
static void
search_add2ldap_func (struct userNode *source, struct handle_info *match, UNUSED_ARG(struct nickserv_discrim *discrim))
{
    int rc;
    if(match->email_addr && match->passwd && match->handle) {
	    rc  = ldap_do_add(match->handle, match->passwd, match->email_addr);
	    if(rc != LDAP_SUCCESS) {
	       send_message(source, nickserv, "NSMSG_LDAP_FAIL_ADD", match->handle, ldap_err2string(rc));
	    }
    }
}
#endif

static void
search_set_func (struct userNode *source, struct handle_info *match, struct nickserv_discrim *discrim)
{
    option_func_t *opt;
    char *oargv[2];
    
    if (!(opt = dict_find(nickserv_opt_dict, discrim->setwhat, NULL))) {
        return;
    }

    oargv[0] = (char *)discrim->setwhat;
    oargv[1] = (char *)discrim->setval;

    opt(discrim->cmd, source, match, 1, 1, 2, oargv);
}

static int
nickserv_sort_accounts_by_access(const void *a, const void *b)
{
    const struct handle_info *hi_a = *(const struct handle_info**)a;
    const struct handle_info *hi_b = *(const struct handle_info**)b;
    if (hi_a->opserv_level != hi_b->opserv_level)
        return hi_b->opserv_level - hi_a->opserv_level;
    return irccasecmp(hi_a->handle, hi_b->handle);
}

void
nickserv_show_oper_accounts(struct userNode *user, struct svccmd *cmd)
{
    struct handle_info_list hil;
    struct helpfile_table tbl;
    unsigned int ii;
    dict_iterator_t it;
    const char **ary;

    memset(&hil, 0, sizeof(hil));
    for (it = dict_first(nickserv_handle_dict); it; it = iter_next(it)) {
        struct handle_info *hi = iter_data(it);
        if (hi->opserv_level)
            handle_info_list_append(&hil, hi);
    }
    qsort(hil.list, hil.used, sizeof(hil.list[0]), nickserv_sort_accounts_by_access);
    tbl.length = hil.used + 1;
    tbl.width = 2;
    tbl.flags = TABLE_NO_FREE | TABLE_REPEAT_ROWS | TABLE_REPEAT_HEADERS;
    tbl.contents = malloc(tbl.length * sizeof(tbl.contents[0]));
    tbl.contents[0] = ary = malloc(tbl.width * sizeof(ary[0]));
    ary[0] = "Account";
    ary[1] = "Level";
    for (ii = 0; ii < hil.used; ) {
        ary = malloc(tbl.width * sizeof(ary[0]));
        ary[0] = hil.list[ii]->handle;
        ary[1] = strtab(hil.list[ii]->opserv_level);
        tbl.contents[++ii] = ary;
    }
    table_send(cmd->parent->bot, user->nick, 0, NULL, tbl);
    /*reply("MSG_MATCH_COUNT", hil.used); */
    for (ii = 0; ii < hil.used; ii++)
        free(tbl.contents[ii]);
    free(tbl.contents);
    free(hil.list);
}

static NICKSERV_FUNC(cmd_search)
{
    struct nickserv_discrim *discrim;
    discrim_search_func action;
    struct svccmd *subcmd;
    unsigned int matches;
    char buf[MAXLEN];

    NICKSERV_MIN_PARMS(3);
    sprintf(buf, "search %s", argv[1]);
    subcmd = dict_find(nickserv_service->commands, buf, NULL);
    if (!irccasecmp(argv[1], "print"))
        action = search_print_func;
    else if (!irccasecmp(argv[1], "count"))
        action = search_count_func;
    else if (!irccasecmp(argv[1], "unregister"))
        action = search_unregister_func;
    else if (!irccasecmp(argv[1], "set"))
        action = search_set_func;
#ifdef WITH_LDAP
    else if (nickserv_conf.ldap_enable && !irccasecmp(argv[1], "add2ldap"))
        action = search_add2ldap_func;
#endif
    else {
        reply("NSMSG_INVALID_ACTION", argv[1]);
        return 0;
    }

    if (subcmd && !svccmd_can_invoke(user, nickserv, subcmd, NULL, SVCCMD_NOISY))
        return 0;

    discrim = nickserv_discrim_create(cmd, user, argc-2, argv+2);
    if (!discrim)
        return 0;

    if (action == search_print_func)
        reply("NSMSG_ACCOUNT_SEARCH_RESULTS");
    else if (action == search_count_func)
        discrim->limit = INT_MAX;
    else if ((action == search_set_func) && (!(discrim->setwhat) || !(discrim->setval)))
       return reply("MSG_MISSING_PARAMS", argv[1]);

    matches = nickserv_discrim_search(discrim, action, user);

    if (matches)
        reply("MSG_MATCH_COUNT", matches);
    else
        reply("MSG_NO_MATCHES");

    free(discrim);
    return 0;
}

static MODCMD_FUNC(cmd_checkpass)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(3);
    if (!(hi = get_handle_info(argv[1]))) {
        reply("MSG_HANDLE_UNKNOWN", argv[1]);
        return 0;
    }
    if (checkpass(argv[2], hi->passwd))
        reply("CHECKPASS_YES");
    else
        reply("CHECKPASS_NO");
    argv[2] = "****";
    return 1;
}

static MODCMD_FUNC(cmd_checkemail)
{
    struct handle_info *hi;

    NICKSERV_MIN_PARMS(3);
    if (!(hi = modcmd_get_handle_info(user, argv[1]))) {
        return 0;
    }
    if (!hi->email_addr)
        reply("CHECKEMAIL_NOT_SET");
    else if (!irccasecmp(argv[2], hi->email_addr))
        reply("CHECKEMAIL_YES");
    else
        reply("CHECKEMAIL_NO");
    return 1;
}

static void
nickserv_db_read_handle(char *handle, dict_t obj)
{
    const char *str;
    struct string_list *masks, *sslfps, *slist, *ignores;
    struct handle_info *hi;
    struct userNode *authed_users;
    struct userData *channel_list;
    struct dict *obj2;
    dict_iterator_t it;
    unsigned long int id;
    unsigned int ii;
    dict_t subdb;
    char *setter, *note;
    time_t date;

    str = database_get_data(obj, KEY_ID, RECDB_QSTRING);
    id = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(obj, KEY_PASSWD, RECDB_QSTRING);
    if (!str) {
        log_module(NS_LOG, LOG_WARNING, "did not find a password for %s -- skipping user.", handle);
        return;
    }
    if ((hi = get_handle_info(handle))) {
        authed_users = hi->users;
        channel_list = hi->channels;
        hi->users = NULL;
        hi->channels = NULL;
        dict_remove(nickserv_handle_dict, hi->handle);
    } else {
        authed_users = NULL;
        channel_list = NULL;
    }
    if(nickserv_conf.force_handles_lowercase)
        irc_strtolower(handle);
    hi = register_handle(handle, str, id);
    if (authed_users) {
        hi->users = authed_users;
        while (authed_users) {
            authed_users->handle_info = hi;
            authed_users = authed_users->next_authed;
        }
    }
    hi->channels = channel_list;
    masks = database_get_data(obj, KEY_MASKS, RECDB_STRING_LIST);
    hi->masks = masks ? string_list_copy(masks) : alloc_string_list(1);
    sslfps = database_get_data(obj, KEY_SSLFPS, RECDB_STRING_LIST);
    hi->sslfps = sslfps ? string_list_copy(sslfps) : alloc_string_list(1);
    ignores = database_get_data(obj, KEY_IGNORES, RECDB_STRING_LIST);
    hi->ignores = ignores ? string_list_copy(ignores) : alloc_string_list(1);
    str = database_get_data(obj, KEY_MAXLOGINS, RECDB_QSTRING);
    hi->maxlogins = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(obj, KEY_LANGUAGE, RECDB_QSTRING);
    hi->language = language_find(str ? str : "C");
    str = database_get_data(obj, KEY_OPSERV_LEVEL, RECDB_QSTRING);
    hi->opserv_level = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(obj, KEY_INFO, RECDB_QSTRING);
    if (str)
        hi->infoline = strdup(str);
    str = database_get_data(obj, KEY_REGISTER_ON, RECDB_QSTRING);
    hi->registered = str ? (time_t)strtoul(str, NULL, 0) : now;
    str = database_get_data(obj, KEY_LAST_SEEN, RECDB_QSTRING);
    hi->lastseen = str ? (time_t)strtoul(str, NULL, 0) : hi->registered;
    str = database_get_data(obj, KEY_KARMA, RECDB_QSTRING);
    hi->karma = str ? strtoul(str, NULL, 0) : 0;
    /* We want to read the nicks even if disable_nicks is set.  This is so
     * that we don't lose the nick data entirely. */
    obj2 = database_get_data(obj, KEY_NICKS_EX, RECDB_OBJECT);
    for(it = dict_first(obj2); it; it = iter_next(it))
    {
        struct record_data *rd = iter_data(it);
        struct nick_info* ni;

        register_nick(iter_key(it), hi);
        ni = get_nick_info(iter_key(it));

        if (!(ni))
            continue;

        str = database_get_data(rd->d.object, KEY_REGISTER_ON, RECDB_QSTRING);
        ni->registered = str ? (time_t)strtoul(str, NULL, 0) : now;
        str = database_get_data(rd->d.object, KEY_LAST_SEEN, RECDB_QSTRING);
        ni->lastseen = str ? (time_t)strtoul(str, NULL, 0) : ni->registered;
    }
    if (!obj2) {
        slist = database_get_data(obj, KEY_NICKS, RECDB_STRING_LIST);
        if (slist) {
            for (ii=0; ii<slist->used; ii++) {
                struct nick_info* ni;

                register_nick(slist->list[ii], hi);
                ni = get_nick_info(slist->list[ii]);

                if (!(ni))
                    continue;

                ni->registered = hi->registered;
                ni->lastseen = ni->registered;
            }
        }
    }
    str = database_get_data(obj, KEY_FLAGS, RECDB_QSTRING);
    if (str) {
        for (ii=0; str[ii]; ii++)
            hi->flags |= 1 << (handle_inverse_flags[(unsigned char)str[ii]] - 1);
    }
    str = database_get_data(obj, KEY_USERLIST_STYLE, RECDB_QSTRING);
    hi->userlist_style = str ? str[0] : HI_DEFAULT_STYLE;
    str = database_get_data(obj, KEY_ANNOUNCEMENTS, RECDB_QSTRING);
    hi->announcements = str ? str[0] : '?';
    str = database_get_data(obj, KEY_SCREEN_WIDTH, RECDB_QSTRING);
    hi->screen_width = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(obj, KEY_TABLE_WIDTH, RECDB_QSTRING);
    hi->table_width = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(obj, KEY_LAST_QUIT_HOST, RECDB_QSTRING);
    if (!str)
        str = database_get_data(obj, KEY_LAST_AUTHED_HOST, RECDB_QSTRING);
    if (str)
        safestrncpy(hi->last_quit_host, str, sizeof(hi->last_quit_host));
    str = database_get_data(obj, KEY_EMAIL_ADDR, RECDB_QSTRING);
    if (str)
        nickserv_set_email_addr(hi, str);
    str = database_get_data(obj, KEY_EPITHET, RECDB_QSTRING);
    if (str)
        hi->epithet = strdup(str);
    subdb = database_get_data(obj, KEY_NOTE_NOTE, RECDB_OBJECT);
    if (subdb) {
        setter = database_get_data(subdb, KEY_NOTE_SETTER, RECDB_QSTRING);
        str = database_get_data(subdb, KEY_NOTE_DATE, RECDB_QSTRING);
        date = str ? (time_t)strtoul(str, NULL, 0) : now;
        note = database_get_data(subdb, KEY_NOTE_NOTE, RECDB_QSTRING);
        if (setter && date && note)
        {
            if (!(hi->note = nickserv_add_note(setter, date, note)))
                hi->note = NULL;
        }
    }

    str = database_get_data(obj, KEY_FAKEHOST, RECDB_QSTRING);
    if (str)
        hi->fakehost = strdup(str);

    subdb = database_get_data(obj, KEY_COOKIE, RECDB_OBJECT);
    if (subdb) {
        const char *data, *type, *expires, *cookie_str;
        struct handle_cookie *cookie;

        cookie = calloc(1, sizeof(*cookie));
        type = database_get_data(subdb, KEY_COOKIE_TYPE, RECDB_QSTRING);
        data = database_get_data(subdb, KEY_COOKIE_DATA, RECDB_QSTRING);
        expires = database_get_data(subdb, KEY_COOKIE_EXPIRES, RECDB_QSTRING);
        cookie_str = database_get_data(subdb, KEY_COOKIE, RECDB_QSTRING);
        if (!type || !expires || !cookie_str) {
            log_module(NS_LOG, LOG_ERROR, "Missing field(s) from cookie for account %s; dropping cookie.", hi->handle);
            goto cookie_out;
        }
        if (!irccasecmp(type, KEY_ACTIVATION))
            cookie->type = ACTIVATION;
        else if (!irccasecmp(type, KEY_PASSWORD_CHANGE))
            cookie->type = PASSWORD_CHANGE;
        else if (!irccasecmp(type, KEY_EMAIL_CHANGE))
            cookie->type = EMAIL_CHANGE;
        else if (!irccasecmp(type, KEY_ALLOWAUTH))
            cookie->type = ALLOWAUTH;
        else {
            log_module(NS_LOG, LOG_ERROR, "Invalid cookie type %s for account %s; dropping cookie.", type, handle);
            goto cookie_out;
        }
        cookie->expires = strtoul(expires, NULL, 0);
        if (cookie->expires < now)
            goto cookie_out;
        if (data)
            cookie->data = strdup(data);
        safestrncpy(cookie->cookie, cookie_str, sizeof(cookie->cookie));
        cookie->hi = hi;
      cookie_out:
        if (cookie->hi)
            nickserv_bake_cookie(cookie);
        else
            nickserv_free_cookie(cookie);
    }
}

static int
nickserv_saxdb_read(dict_t db) {
    dict_iterator_t it;
    struct record_data *rd;
    char *handle;

    for (it=dict_first(db); it; it=iter_next(it)) {
        rd = iter_data(it);
        handle = strdup(iter_key(it));
        nickserv_db_read_handle(handle, rd->d.object);
        free(handle);
    }
    return 0;
}

static NICKSERV_FUNC(cmd_mergedb)
{
    struct timeval start, stop;
    dict_t db;

    NICKSERV_MIN_PARMS(2);
    gettimeofday(&start, NULL);
    if (!(db = parse_database(argv[1]))) {
        reply("NSMSG_DB_UNREADABLE", argv[1]);
        return 0;
    }
    nickserv_saxdb_read(db);
    free_database(db);
    gettimeofday(&stop, NULL);
    stop.tv_sec -= start.tv_sec;
    stop.tv_usec -= start.tv_usec;
    if (stop.tv_usec < 0) {
	stop.tv_sec -= 1;
	stop.tv_usec += 1000000;
    }
    reply("NSMSG_DB_MERGED", argv[1], stop.tv_sec, stop.tv_usec/1000);
    return 1;
}

static void
expire_handles(UNUSED_ARG(void *data))
{
    dict_iterator_t it, next;
    time_t expiry;
    struct handle_info *hi;

    for (it=dict_first(nickserv_handle_dict); it; it=next) {
        next = iter_next(it);
        hi = iter_data(it);
        if ((hi->opserv_level > 0)
            || hi->users
            || HANDLE_FLAGGED(hi, FROZEN)
            || HANDLE_FLAGGED(hi, NODELETE)) {
            continue;
        }
        expiry = hi->channels ? nickserv_conf.handle_expire_delay : nickserv_conf.nochan_handle_expire_delay;
        if ((now - hi->lastseen) > expiry) {
            log_module(NS_LOG, LOG_INFO, "Expiring account %s for inactivity.", hi->handle);
            nickserv_unregister_handle(hi, NULL, NULL);
        }
    }

    if (nickserv_conf.handle_expire_frequency)
        timeq_add(now + nickserv_conf.handle_expire_frequency, expire_handles, NULL);
}

static void
expire_nicks(UNUSED_ARG(void *data))
{
    dict_iterator_t it, next;
    time_t expiry = nickserv_conf.nick_expire_delay;
    struct nick_info *ni;
    struct userNode *ui;

    if (!(nickserv_conf.expire_nicks))
        return;

    for (it=dict_first(nickserv_nick_dict); it; it=next) {
        next = iter_next(it);
        ni = iter_data(it);
        if ((ni->owner->opserv_level > 0)
            || ((ui = GetUserH(ni->nick)) && (ui->handle_info) && (ui->handle_info == ni->owner))
            || HANDLE_FLAGGED(ni->owner, FROZEN)
            || HANDLE_FLAGGED(ni->owner, NODELETE)) {
            continue;
        }
        if ((now - ni->lastseen) > expiry) {
            log_module(NS_LOG, LOG_INFO, "Expiring nick %s for inactivity.", ni->nick);
            delete_nick(ni);
        }
    }

    if (nickserv_conf.nick_expire_frequency && nickserv_conf.expire_nicks)
        timeq_add(now + nickserv_conf.nick_expire_frequency, expire_nicks, NULL);
}

static void
nickserv_load_dict(const char *fname)
{
    FILE *file;
    char line[128];
    if (!(file = fopen(fname, "r"))) {
        log_module(NS_LOG, LOG_ERROR, "Unable to open dictionary file %s: %s", fname, strerror(errno));
        return;
    }
    while (fgets(line, sizeof(line), file)) {
        if (!line[0])
            continue;
        if (line[strlen(line)-1] == '\n')
            line[strlen(line)-1] = 0;
        dict_insert(nickserv_conf.weak_password_dict, strdup(line), NULL);
    }
    fclose(file);
    log_module(NS_LOG, LOG_INFO, "Loaded %d words into weak password dictionary.", dict_size(nickserv_conf.weak_password_dict));
}

static enum reclaim_action
reclaim_action_from_string(const char *str) {
    if (!str)
        return RECLAIM_NONE;
    else if (!irccasecmp(str, "warn"))
        return RECLAIM_WARN;
    else if (!irccasecmp(str, "svsnick"))
        return RECLAIM_SVSNICK;
    else if (!irccasecmp(str, "kill"))
        return RECLAIM_KILL;
    else
        return RECLAIM_NONE;
}

static void
nickserv_conf_read(void)
{
    dict_t conf_node, child;
    const char *str;
    dict_iterator_t it;
    struct string_list *strlist;

    if (!(conf_node = conf_get_data(NICKSERV_CONF_NAME, RECDB_OBJECT))) {
	log_module(NS_LOG, LOG_ERROR, "config node `%s' is missing or has wrong type.", NICKSERV_CONF_NAME);
	return;
    }
    str = database_get_data(conf_node, KEY_VALID_HANDLE_REGEX, RECDB_QSTRING);
    if (!str)
        str = database_get_data(conf_node, KEY_VALID_ACCOUNT_REGEX, RECDB_QSTRING);
    if (nickserv_conf.valid_handle_regex_set)
        regfree(&nickserv_conf.valid_handle_regex);
    if (str) {
        int err = regcomp(&nickserv_conf.valid_handle_regex, str, REG_EXTENDED|REG_ICASE|REG_NOSUB);
        nickserv_conf.valid_handle_regex_set = !err;
        if (err) log_module(NS_LOG, LOG_ERROR, "Bad valid_account_regex (error %d)", err);
    } else {
        nickserv_conf.valid_handle_regex_set = 0;
    }
    str = database_get_data(conf_node, KEY_VALID_NICK_REGEX, RECDB_QSTRING);
    if (nickserv_conf.valid_nick_regex_set)
        regfree(&nickserv_conf.valid_nick_regex);
    if (str) {
        int err = regcomp(&nickserv_conf.valid_nick_regex, str, REG_EXTENDED|REG_ICASE|REG_NOSUB);
        nickserv_conf.valid_nick_regex_set = !err;
        if (err) log_module(NS_LOG, LOG_ERROR, "Bad valid_nick_regex (error %d)", err);
    } else {
        nickserv_conf.valid_nick_regex_set = 0;
    }
    str = database_get_data(conf_node, KEY_VALID_FAKEHOST_REGEX, RECDB_QSTRING);
    if (nickserv_conf.valid_fakehost_regex_set)
        regfree(&nickserv_conf.valid_fakehost_regex);
    if (str) {
        int err = regcomp(&nickserv_conf.valid_fakehost_regex, str, REG_EXTENDED|REG_ICASE|REG_NOSUB);
        nickserv_conf.valid_fakehost_regex_set = !err;
        if (err) log_module(NS_LOG, LOG_ERROR, "Bad valid_fakehost_regex (error %d)", err);
    } else {
        nickserv_conf.valid_fakehost_regex_set = 0;
    }
    str = database_get_data(conf_node, KEY_NICKS_PER_HANDLE, RECDB_QSTRING);
    if (!str)
        str = database_get_data(conf_node, KEY_NICKS_PER_ACCOUNT, RECDB_QSTRING);
    nickserv_conf.nicks_per_handle = str ? strtoul(str, NULL, 0) : 4;
    str = database_get_data(conf_node, KEY_DISABLE_NICKS, RECDB_QSTRING);
    nickserv_conf.disable_nicks = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(conf_node, KEY_DEFAULT_HOSTMASK, RECDB_QSTRING);
    nickserv_conf.default_hostmask = str ? !disabled_string(str) : 0;
    str = database_get_data(conf_node, KEY_PASSWORD_MIN_LENGTH, RECDB_QSTRING);
    nickserv_conf.password_min_length = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(conf_node, KEY_PASSWORD_MIN_DIGITS, RECDB_QSTRING);
    nickserv_conf.password_min_digits = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(conf_node, KEY_PASSWORD_MIN_UPPER, RECDB_QSTRING);
    nickserv_conf.password_min_upper = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(conf_node, KEY_PASSWORD_MIN_LOWER, RECDB_QSTRING);
    nickserv_conf.password_min_lower = str ? strtoul(str, NULL, 0) : 0;
    str = database_get_data(conf_node, KEY_DB_BACKUP_FREQ, RECDB_QSTRING);
    nickserv_conf.db_backup_frequency = str ? ParseInterval(str) : 7200;
    str = database_get_data(conf_node, KEY_MODOPER_LEVEL, RECDB_QSTRING);
    nickserv_conf.modoper_level = str ? strtoul(str, NULL, 0) : 900;
    str = database_get_data(conf_node, KEY_SET_EPITHET_LEVEL, RECDB_QSTRING);
    nickserv_conf.set_epithet_level = str ? strtoul(str, NULL, 0) : 1;
    str = database_get_data(conf_node, KEY_SET_TITLE_LEVEL, RECDB_QSTRING);
    nickserv_conf.set_title_level = str ? strtoul(str, NULL, 0) : 900;
    str = database_get_data(conf_node, KEY_SET_FAKEHOST_LEVEL, RECDB_QSTRING);
    nickserv_conf.set_fakehost_level = str ? strtoul(str, NULL, 0) : 1000;
    str = database_get_data(conf_node, KEY_HANDLE_EXPIRE_FREQ, RECDB_QSTRING);
    if (!str)
        str = database_get_data(conf_node, KEY_ACCOUNT_EXPIRE_FREQ, RECDB_QSTRING);
    nickserv_conf.handle_expire_frequency = str ? ParseInterval(str) : 86400;
    str = database_get_data(conf_node, KEY_HANDLE_EXPIRE_DELAY, RECDB_QSTRING);
    if (!str)
        str = database_get_data(conf_node, KEY_ACCOUNT_EXPIRE_DELAY, RECDB_QSTRING);
    nickserv_conf.handle_expire_delay = str ? ParseInterval(str) : 86400*30;
    str = database_get_data(conf_node, KEY_NOCHAN_HANDLE_EXPIRE_DELAY, RECDB_QSTRING);
    if (!str)
        str = database_get_data(conf_node, KEY_NOCHAN_ACCOUNT_EXPIRE_DELAY, RECDB_QSTRING);
    nickserv_conf.nochan_handle_expire_delay = str ? ParseInterval(str) : 86400*15;
    str = database_get_data(conf_node, "warn_clone_auth", RECDB_QSTRING);
    nickserv_conf.warn_clone_auth = str ? !disabled_string(str) : 1;
    str = database_get_data(conf_node, "default_maxlogins", RECDB_QSTRING);
    nickserv_conf.default_maxlogins = str ? strtoul(str, NULL, 0) : 2;
    str = database_get_data(conf_node, "hard_maxlogins", RECDB_QSTRING);
    nickserv_conf.hard_maxlogins = str ? strtoul(str, NULL, 0) : 10;
    str = database_get_data(conf_node, KEY_OUNREGISTER_INACTIVE, RECDB_QSTRING);
    nickserv_conf.ounregister_inactive = str ? ParseInterval(str) : 86400*28;
    str = database_get_data(conf_node, KEY_OUNREGISTER_FLAGS, RECDB_QSTRING);
    if (!str)
        str = "ShgsfnHbu";
    nickserv_conf.ounregister_flags = 0;
    while(*str) {
        unsigned int pos = handle_inverse_flags[(unsigned char)*str];
        str++;
        if(pos)
            nickserv_conf.ounregister_flags |= 1 << (pos - 1);
    }
    if (!nickserv_conf.disable_nicks) {
        str = database_get_data(conf_node, "reclaim_action", RECDB_QSTRING);
        nickserv_conf.reclaim_action = str ? reclaim_action_from_string(str) : RECLAIM_NONE;
        str = database_get_data(conf_node, "warn_nick_owned", RECDB_QSTRING);
        nickserv_conf.warn_nick_owned = str ? enabled_string(str) : 0;
        str = database_get_data(conf_node, "auto_reclaim_action", RECDB_QSTRING);
        nickserv_conf.auto_reclaim_action = str ? reclaim_action_from_string(str) : RECLAIM_NONE;
        str = database_get_data(conf_node, "auto_reclaim_delay", RECDB_QSTRING);
        nickserv_conf.auto_reclaim_delay = str ? ParseInterval(str) : 0;
        str = database_get_data(conf_node, KEY_NICK_EXPIRE_FREQ, RECDB_QSTRING);
        nickserv_conf.nick_expire_frequency = str ? ParseInterval(str) : 86400;
        str = database_get_data(conf_node, KEY_NICK_EXPIRE_DELAY, RECDB_QSTRING);
        nickserv_conf.nick_expire_delay = str ? ParseInterval(str) : 86400*30;
        str = database_get_data(conf_node, "expire_nicks", RECDB_QSTRING);
        nickserv_conf.expire_nicks = str ? enabled_string(str) : 0;
    }
    child = database_get_data(conf_node, KEY_FLAG_LEVELS, RECDB_OBJECT);
    for (it=dict_first(child); it; it=iter_next(it)) {
        const char *key = iter_key(it), *value;
        unsigned char flag;
        int pos;

        if (!strncasecmp(key, "uc_", 3))
            flag = toupper(key[3]);
        else if (!strncasecmp(key, "lc_", 3))
            flag = tolower(key[3]);
        else
            flag = key[0];

        if ((pos = handle_inverse_flags[flag])) {
            value = GET_RECORD_QSTRING((struct record_data*)iter_data(it));
            flag_access_levels[pos - 1] = strtoul(value, NULL, 0);
        }
    }
    if (nickserv_conf.weak_password_dict)
        dict_delete(nickserv_conf.weak_password_dict);
    nickserv_conf.weak_password_dict = dict_new();
    dict_set_free_keys(nickserv_conf.weak_password_dict, free);
    dict_insert(nickserv_conf.weak_password_dict, strdup("password"), NULL);
    dict_insert(nickserv_conf.weak_password_dict, strdup("<password>"), NULL);
    str = database_get_data(conf_node, KEY_DICT_FILE, RECDB_QSTRING);
    if (str)
        nickserv_load_dict(str);
    str = database_get_data(conf_node, KEY_NICK, RECDB_QSTRING);
    if (nickserv && str)
        NickChange(nickserv, str, 0);
    str = database_get_data(conf_node, KEY_AUTOGAG_ENABLED, RECDB_QSTRING);
    nickserv_conf.autogag_enabled = str ? strtoul(str, NULL, 0) : 1;
    str = database_get_data(conf_node, KEY_AUTOGAG_DURATION, RECDB_QSTRING);
    nickserv_conf.autogag_duration = str ? ParseInterval(str) : 1800;
    str = database_get_data(conf_node, KEY_EMAIL_VISIBLE_LEVEL, RECDB_QSTRING);
    nickserv_conf.email_visible_level = str ? strtoul(str, NULL, 0) : 800;
    str = database_get_data(conf_node, KEY_EMAIL_ENABLED, RECDB_QSTRING);
    nickserv_conf.email_enabled = str ? enabled_string(str) : 0;
    str = database_get_data(conf_node, KEY_SYNC_LOG, RECDB_QSTRING);
    nickserv_conf.sync_log = str ? enabled_string(str) : 0;
    str = database_get_data(conf_node, KEY_COOKIE_TIMEOUT, RECDB_QSTRING);
    nickserv_conf.cookie_timeout = str ? ParseInterval(str) : 24*3600;
    str = database_get_data(conf_node, KEY_EMAIL_REQUIRED, RECDB_QSTRING);
    nickserv_conf.email_required = (nickserv_conf.email_enabled && str) ? enabled_string(str) : 0;
    str = database_get_data(conf_node, KEY_ACCOUNTS_PER_EMAIL, RECDB_QSTRING);
    nickserv_conf.handles_per_email = str ? strtoul(str, NULL, 0) : 1;
    str = database_get_data(conf_node, KEY_EMAIL_SEARCH_LEVEL, RECDB_QSTRING);
    nickserv_conf.email_search_level = str ? strtoul(str, NULL, 0) : 600;
    str = database_get_data(conf_node, KEY_TITLEHOST_SUFFIX, RECDB_QSTRING);
    nickserv_conf.titlehost_suffix = str ? str : "example.net";

    free_string_list(nickserv_conf.denied_fakehost_words);
    strlist = database_get_data(conf_node, KEY_DENIED_FAKEHOST_WORDS, RECDB_STRING_LIST);
    if(strlist)
        strlist = string_list_copy(strlist);
    else {
        strlist = alloc_string_list(4);
        string_list_append(strlist, strdup("sex"));
        string_list_append(strlist, strdup("fuck"));
    }
    nickserv_conf.denied_fakehost_words = strlist;

    str = database_get_data(conf_node, KEY_DEFAULT_STYLE, RECDB_QSTRING);
    nickserv_conf.default_style = str ? str[0] : HI_DEFAULT_STYLE;

    str = database_get_data(conf_node, KEY_AUTO_OPER, RECDB_QSTRING);
    nickserv_conf.auto_oper = str ? str : "";

    str = database_get_data(conf_node, KEY_AUTO_ADMIN, RECDB_QSTRING);
    nickserv_conf.auto_admin = str ? str : "";

    str = database_get_data(conf_node, KEY_AUTO_OPER_PRIVS, RECDB_QSTRING);
    nickserv_conf.auto_oper_privs = str ? str : "";

    str = database_get_data(conf_node, KEY_AUTO_ADMIN_PRIVS, RECDB_QSTRING);
    nickserv_conf.auto_admin_privs = str ? str : "";

    str = conf_get_data("server/network", RECDB_QSTRING);
    nickserv_conf.network_name = str ? str : "some IRC network";
    if (!nickserv_conf.auth_policer_params) {
        nickserv_conf.auth_policer_params = policer_params_new();
        policer_params_set(nickserv_conf.auth_policer_params, "size", "5");
        policer_params_set(nickserv_conf.auth_policer_params, "drain-rate", "0.05");
    }
    child = database_get_data(conf_node, KEY_AUTH_POLICER, RECDB_OBJECT);
    for (it=dict_first(child); it; it=iter_next(it))
        set_policer_param(iter_key(it), iter_data(it), nickserv_conf.auth_policer_params);

    str = database_get_data(conf_node, KEY_LDAP_ENABLE, RECDB_QSTRING);
    nickserv_conf.ldap_enable = str ? strtoul(str, NULL, 0) : 0;

    str = database_get_data(conf_node, KEY_FORCE_HANDLES_LOWERCASE, RECDB_QSTRING);
    nickserv_conf.force_handles_lowercase = str ? strtol(str, NULL, 0) : 0;

#ifndef WITH_LDAP
    if(nickserv_conf.ldap_enable > 0) {
        /* ldap is enabled but not compiled in - error out */
        log_module(MAIN_LOG, LOG_ERROR, "ldap is enabled in config, but not compiled in!");
        exit(2);
        /* nickserv_conf.ldap_enable = 0; */
        /* sleep(5); */
    }
#endif 

#ifdef WITH_LDAP
    str = database_get_data(conf_node, KEY_LDAP_URI, RECDB_QSTRING);
    nickserv_conf.ldap_uri = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_BASE, RECDB_QSTRING);
    nickserv_conf.ldap_base = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_DN_FMT, RECDB_QSTRING);
    nickserv_conf.ldap_dn_fmt = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_VERSION, RECDB_QSTRING);
    nickserv_conf.ldap_version = str ? strtoul(str, NULL, 0) : 3;

    str = database_get_data(conf_node, KEY_LDAP_AUTOCREATE, RECDB_QSTRING);
    nickserv_conf.ldap_autocreate = str ? strtoul(str, NULL, 0) : 0;

    str = database_get_data(conf_node, KEY_LDAP_TIMEOUT, RECDB_QSTRING);
    nickserv_conf.ldap_timeout = str ? strtoul(str, NULL, 0) : 5;

    str = database_get_data(conf_node, KEY_LDAP_ADMIN_DN, RECDB_QSTRING);
    nickserv_conf.ldap_admin_dn = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_ADMIN_PASS, RECDB_QSTRING);
    nickserv_conf.ldap_admin_pass = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_FIELD_ACCOUNT, RECDB_QSTRING);
    nickserv_conf.ldap_field_account = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_FIELD_PASSWORD, RECDB_QSTRING);
    nickserv_conf.ldap_field_password = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_FIELD_EMAIL, RECDB_QSTRING);
    nickserv_conf.ldap_field_email = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_FIELD_OSLEVEL, RECDB_QSTRING);
    nickserv_conf.ldap_field_oslevel = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_OPER_GROUP_DN, RECDB_QSTRING);
    nickserv_conf.ldap_oper_group_dn = str ? str : "";

    str = database_get_data(conf_node, KEY_LDAP_OPER_GROUP_LEVEL, RECDB_QSTRING);
    nickserv_conf.ldap_oper_group_level = str ? strtoul(str, NULL, 0) : 99;

    str = database_get_data(conf_node, KEY_LDAP_FIELD_GROUP_MEMBER, RECDB_QSTRING);
    nickserv_conf.ldap_field_group_member = str ? str : "";

    free_string_list(nickserv_conf.ldap_object_classes);
    strlist = database_get_data(conf_node, KEY_LDAP_OBJECT_CLASSES, RECDB_STRING_LIST);
    if(strlist)
        strlist = string_list_copy(strlist);
    else {
        strlist = alloc_string_list(4);
        string_list_append(strlist, strdup("top"));
    }
    nickserv_conf.ldap_object_classes = strlist;

#endif

}

static void
nickserv_reclaim(struct userNode *user, struct nick_info *ni, enum reclaim_action action) {
    const char *msg;
    char newnick[NICKLEN+1];

    assert(user);
    assert(ni);

    if (IsLocal(user))
        return;

    switch (action) {
    case RECLAIM_NONE:
        /* do nothing */
        break;
    case RECLAIM_WARN:
        send_message(user, nickserv, "NSMSG_RECLAIM_WARN", ni->nick, ni->owner->handle);
        send_message(user, nickserv, "NSMSG_RECLAIM_HOWTO", ni->owner->handle, nickserv->nick, self->name, ni->owner->handle);
        break;
    case RECLAIM_SVSNICK:
        do {
            snprintf(newnick, sizeof(newnick), "Guest%d", rand()%10000);
        } while (GetUserH(newnick));
        irc_svsnick(nickserv, user, newnick);
        break;
    case RECLAIM_KILL:
        msg = user_find_message(user, "NSMSG_RECLAIM_KILL");
        DelUser(user, nickserv, 1, msg);
        break;
    }
}

static void
nickserv_reclaim_p(void *data) {
    struct userNode *user = data;
    struct nick_info *ni = get_nick_info(user->nick);
    if (ni)
        nickserv_reclaim(user, ni, nickserv_conf.auto_reclaim_action);
}

static int
check_user_nick(struct userNode *user, UNUSED_ARG(void *extra)) {
    struct nick_info *ni;
    user->modes &= ~FLAGS_REGNICK;

    if (!(ni = get_nick_info(user->nick)))
        return 0;
    if (user->handle_info == ni->owner) {
        user->modes |= FLAGS_REGNICK;
        irc_regnick(user);
        return 0;
    }
    if (nickserv_conf.warn_nick_owned) {
        send_message(user, nickserv, "NSMSG_RECLAIM_WARN", ni->nick, ni->owner->handle);
        send_message(user, nickserv, "NSMSG_RECLAIM_HOWTO", ni->owner->handle, nickserv->nick, self->name, ni->owner->handle);
    }
    if (nickserv_conf.auto_reclaim_action == RECLAIM_NONE)
        return 0;
    if (nickserv_conf.auto_reclaim_delay)
        timeq_add(now + nickserv_conf.auto_reclaim_delay, nickserv_reclaim_p, user);
    else
        nickserv_reclaim(user, ni, nickserv_conf.auto_reclaim_action);

    return 0;
}

static int
new_user_event(struct userNode *user, void *extra) {
    /* If the user's server is not bursting,
     * the user is authed, the account has autohide set
     * and the user doesn't have user mode +x then apply
     * the autohide setting.
     */
    if (!user->uplink->burst && user->handle_info &&
        HANDLE_FLAGGED(user->handle_info, AUTOHIDE) &&
        !IsHiddenHost(user))
        irc_umode(user, "+x");

    return check_user_nick(user, extra);
}

void
handle_account(struct userNode *user, const char *stamp)
{
    struct handle_info *hi;
    char *colon;

#ifdef WITH_PROTOCOL_P10
    time_t timestamp = 0;

    colon = strchr(stamp, ':');
    if(colon && colon[1])
    {
        *colon = 0;
        timestamp = atoi(colon+1);
    }
    hi = dict_find(nickserv_handle_dict, stamp, NULL);
    if(hi && timestamp && hi->registered != timestamp)
    {
        log_module(MAIN_LOG, LOG_WARNING, "%s using account %s but timestamp does not match %s is not %s.", user->nick, stamp, ctime(&timestamp), 
ctime(&hi->registered));
        return;
    }
#else
    hi = dict_find(nickserv_id_dict, stamp, NULL);
    log_module(MAIN_LOG, LOG_WARNING, "Using non-P10 code in accounts, not tested at all!");
#endif

#ifdef WITH_LDAP
    if(!hi && nickserv_conf.ldap_enable && nickserv_conf.ldap_autocreate &&
       (ldap_user_exists(stamp) == LDAP_SUCCESS)) {
        int rc = 0;
        int cont = 1;
        char *email = NULL;
        char *mask;

        /* First attempt to get the email address from LDAP */
        if((rc = ldap_get_user_info(stamp, &email) != LDAP_SUCCESS))
            if(nickserv_conf.email_required)
                cont = 0;

        /* Now try to register the handle */
        if (cont && (hi = nickserv_register(user, user, stamp, NULL, 1))) {
            if(nickserv_conf.default_hostmask)
                mask = "*@*";
            else
                mask = generate_hostmask(user, GENMASK_OMITNICK|GENMASK_NO_HIDING|GENMASK_ANY_IDENT);

            if(mask) {
                char* mask_canonicalized = canonicalize_hostmask(strdup(mask));
                string_list_append(hi->masks, mask_canonicalized);
            }

            if(email) {
                nickserv_set_email_addr(hi, email);
                free(email);
            }
        }
    }
#endif

    if (hi) {
        if (HANDLE_FLAGGED(hi, SUSPENDED)) {
            return;
        }
        set_user_handle_info(user, hi, 0);
    } else {
        log_module(MAIN_LOG, LOG_WARNING, "%s had unknown account stamp %s.", user->nick, stamp);
    }
}

void
handle_nick_change(struct userNode *user, const char *old_nick, UNUSED_ARG(void *extra))
{
    struct handle_info *hi;

    if ((hi = dict_find(nickserv_allow_auth_dict, old_nick, 0))) {
        dict_remove(nickserv_allow_auth_dict, old_nick);
        dict_insert(nickserv_allow_auth_dict, user->nick, hi);
    }
    timeq_del(0, nickserv_reclaim_p, user, TIMEQ_IGNORE_WHEN);
    check_user_nick(user, NULL);
}

void
nickserv_remove_user(struct userNode *user, UNUSED_ARG(struct userNode *killer), UNUSED_ARG(const char *why), UNUSED_ARG(void *extra))
{
    dict_remove(nickserv_allow_auth_dict, user->nick);
    timeq_del(0, nickserv_reclaim_p, user, TIMEQ_IGNORE_WHEN);
    set_user_handle_info(user, NULL, 0);
}

static struct modcmd *
nickserv_define_func(const char *name, modcmd_func_t func, int min_level, int must_auth, int must_be_qualified)
{
    if (min_level > 0) {
        char buf[16];
        sprintf(buf, "%u", min_level);
        if (must_be_qualified) {
            return modcmd_register(nickserv_module, name, func, 1, (must_auth ? MODCMD_REQUIRE_AUTHED : 0), "level", buf, "flags", "+qualified,+loghostmask", NULL);
        } else {
            return modcmd_register(nickserv_module, name, func, 1, (must_auth ? MODCMD_REQUIRE_AUTHED : 0), "level", buf, NULL);
        }
    } else if (min_level == 0) {
        if (must_be_qualified) {
            return modcmd_register(nickserv_module, name, func, 1, (must_auth ? MODCMD_REQUIRE_AUTHED : 0), "flags", "+helping", NULL);
        } else {
            return modcmd_register(nickserv_module, name, func, 1, (must_auth ? MODCMD_REQUIRE_AUTHED : 0), "flags", "+helping", NULL);
        }
    } else {
        if (must_be_qualified) {
            return modcmd_register(nickserv_module, name, func, 1, (must_auth ? MODCMD_REQUIRE_AUTHED : 0), "flags", "+qualified,+loghostmask", NULL);
        } else {
            return modcmd_register(nickserv_module, name, func, 1, (must_auth ? MODCMD_REQUIRE_AUTHED : 0), NULL);
        }
    }
}

#define SDFLAG_STALE 0x01  /**< SASL session data is stale, delete on next pass. */

struct SASLSession
{
    struct SASLSession *next;
    struct SASLSession *prev;
    struct server* source;
    char *buf, *p;
    int buflen;
    char uid[128];
    char mech[10];
    char *sslclifp;
    char *hostmask;
    int flags;
};

struct SASLSession *saslsessions = NULL;

void
sasl_delete_session(struct SASLSession *session)
{
    if (!session)
        return;

    if (session->buf)
        free(session->buf);
    session->buf = NULL;

    if (session->sslclifp)
        free(session->sslclifp);
    session->sslclifp = NULL;

    if (session->hostmask)
        free(session->hostmask);
    session->hostmask = NULL;

    if (session->next)
        session->next->prev = session->prev;
    if (session->prev)
        session->prev->next = session->next;
    else
        saslsessions = session->next;

    free(session);
}

void
sasl_delete_stale(UNUSED_ARG(void *data))
{
    int delcount = 0;
    int remcount = 0;
    struct SASLSession *sess = NULL;
    struct SASLSession *nextsess = NULL;

    log_module(NS_LOG, LOG_DEBUG, "SASL: Checking for stale sessions");

    for (sess = saslsessions; sess; sess = nextsess)
    {
        nextsess = sess->next;

        if (sess->flags & SDFLAG_STALE)
        {
            delcount++;
            sasl_delete_session(sess);
        }
        else
        {
            remcount++;
            sess->flags |= SDFLAG_STALE;
        }
    }

    if (delcount)
        log_module(NS_LOG, LOG_DEBUG, "SASL: Deleted %d stale sessions, %d remaining", delcount, remcount);
    if (remcount)
        timeq_add(now + 30, sasl_delete_stale, NULL);
}

struct SASLSession*
sasl_get_session(const char *uid)
{
    struct SASLSession *sess;

    for (sess = saslsessions; sess; sess = sess->next)
    {
        if (!strncmp(sess->uid, uid, 128))
        {
            log_module(NS_LOG, LOG_DEBUG, "SASL: Found session for %s", sess->uid);
            return sess;
        }
    }

    sess = malloc(sizeof(struct SASLSession));
    memset(sess, 0, sizeof(struct SASLSession));

    strncpy(sess->uid, uid, 128);

    if (!saslsessions)
        timeq_add(now + 30, sasl_delete_stale, NULL);

    if (saslsessions)
        saslsessions->prev = sess;
    sess->next = saslsessions;
    saslsessions = sess;

    log_module(NS_LOG, LOG_DEBUG, "SASL: Created session for %s", sess->uid);
    return sess;
}

void
sasl_packet(struct SASLSession *session)
{
    log_module(NS_LOG, LOG_DEBUG, "SASL: Got packet containing: %s", session->buf);

    if (!session->mech[0])
    {
        log_module(NS_LOG, LOG_DEBUG, "SASL: No mechanism stored yet, using %s", session->buf);
        if (strcmp(session->buf, "PLAIN") && (strcmp(session->buf, "EXTERNAL") || !session->sslclifp)) {
            if (!session->sslclifp)
                irc_sasl(session->source, session->uid, "M", "PLAIN");
            else
                irc_sasl(session->source, session->uid, "M", "PLAIN,EXTERNAL");
            irc_sasl(session->source, session->uid, "D", "F");
            sasl_delete_session(session);
            return;
        }

        strncpy(session->mech, session->buf, 10);
        irc_sasl(session->source, session->uid, "C", "+");
    }
    else if (!strcmp(session->mech, "EXTERNAL"))
    {
        char *raw = NULL;
        size_t rawlen = 0;
        char *authzid = NULL;
        struct handle_info *hi = NULL;
        static char buffer[256];

        base64_decode_alloc(session->buf, session->buflen, &raw, &rawlen);

        if (rawlen != 0)
            authzid = raw;

        log_module(NS_LOG, LOG_DEBUG, "SASL: Checking supplied credentials");

        if (!session->sslclifp) {
            log_module(NS_LOG, LOG_DEBUG, "SASL: Incomplete credentials supplied");
            irc_sasl(session->source, session->uid, "D", "F");
        } else {
            if (!(hi = loc_auth(session->sslclifp, authzid, NULL, session->hostmask)))
            {
                log_module(NS_LOG, LOG_DEBUG, "SASL: Invalid credentials supplied");
                irc_sasl(session->source, session->uid, "D", "F");
            }
            else
            {
                snprintf(buffer, sizeof(buffer), "%s "FMT_TIME_T, hi->handle, hi->registered);
                log_module(NS_LOG, LOG_DEBUG, "SASL: Valid credentials supplied");
                irc_sasl(session->source, session->uid, "L", buffer);
                irc_sasl(session->source, session->uid, "D", "S");
            }
        }

        sasl_delete_session(session);

        free(raw);
        return;
    }
    else
    {
        char *raw = NULL;
        size_t rawlen = 0;
        char *authzid = NULL;
        char *authcid = NULL;
        char *passwd = NULL;
        char *r = NULL;
        unsigned int i = 0, c = 0;
        struct handle_info *hi = NULL;
        struct handle_info *hii = NULL;
        static char buffer[256];

        base64_decode_alloc(session->buf, session->buflen, &raw, &rawlen);

        raw = (char *)realloc(raw, rawlen+1);
        raw[rawlen] = '\0';

        authzid = raw;
        r = raw;
        for (i=0; i<rawlen; i++)
        {
            if (!*r++)
            {
                if (c++)
                    passwd = r;
                else
                    authcid = r;
            }
        }

        log_module(NS_LOG, LOG_DEBUG, "SASL: Checking supplied credentials");

        if ((c != 2) || !(*authcid))
        {
            log_module(NS_LOG, LOG_DEBUG, "SASL: Incomplete credentials supplied");
            irc_sasl(session->source, session->uid, "D", "F");
        }
        else
        {
            if (!(hi = loc_auth(session->sslclifp, authcid, passwd, session->hostmask)))
            {
                log_module(NS_LOG, LOG_DEBUG, "SASL: Invalid credentials supplied");
                irc_sasl(session->source, session->uid, "D", "F");
            }
            else
            {
                if (*authzid && irccasecmp(authzid, authcid))
                {
                    if (HANDLE_FLAGGED(hi, IMPERSONATE))
                    {
                        hii = hi;
                        hi = get_handle_info(authzid);
                    }
                    else
                    {
                        log_module(NS_LOG, LOG_DEBUG, "SASL: Impersonation unauthorized");
                        hi = NULL;
                    }
                }
                if (hi)
                {
                    if (hii)
                    {
                        log_module(NS_LOG, LOG_DEBUG, "SASL: %s is ipersonating %s", hii->handle, hi->handle);
                        snprintf(buffer, sizeof(buffer), "%s "FMT_TIME_T, hii->handle, hii->registered);
                        irc_sasl(session->source, session->uid, "I", buffer);
                    }
                    log_module(NS_LOG, LOG_DEBUG, "SASL: Valid credentials supplied");
                    snprintf(buffer, sizeof(buffer), "%s "FMT_TIME_T, hi->handle, hi->registered);
                    irc_sasl(session->source, session->uid, "L", buffer);
                    irc_sasl(session->source, session->uid, "D", "S");
                }
                else
                {
                    log_module(NS_LOG, LOG_DEBUG, "SASL: Invalid credentials supplied");
                    irc_sasl(session->source, session->uid, "D", "F");
                }
            }
        }

        sasl_delete_session(session);

        free(raw);
        return;
    }

    /* clear stale state */
    session->flags &= ~SDFLAG_STALE;
}

void
handle_sasl_input(struct server* source ,const char *uid, const char *subcmd, const char *data, const char *ext, UNUSED_ARG(void *extra))
{
    struct SASLSession* sess = sasl_get_session(uid);
    int len = strlen(data);

    sess->source = source;

    if (!strcmp(subcmd, "D"))
    {
        sasl_delete_session(sess);
        return;
    }

    if (!strcmp(subcmd, "H")) {
       log_module(NS_LOG, LOG_DEBUG, "SASL: Storing host mask %s", data);
       sess->hostmask = strdup(data);
       return ;
    }

    if (strcmp(subcmd, "S") && strcmp(subcmd, "C"))
        return;

    if (len == 0)
        return;

    if (sess->p == NULL)
    {
        sess->buf = (char *)malloc(len + 1);
        sess->p = sess->buf;
        sess->buflen = len;
    }
    else
    {
        if (sess->buflen + len + 1 > 8192) /* This is a little much... */
        {
            irc_sasl(source, uid, "D", "F");
            sasl_delete_session(sess);
            return;
        }

        sess->buf = (char *)realloc(sess->buf, sess->buflen + len + 1);
        sess->p = sess->buf + sess->buflen;
        sess->buflen += len;
    }

    memcpy(sess->p, data, len);
    sess->buf[len] = '\0';

    if (ext != NULL)
        sess->sslclifp = strdup(ext);

    /* Messages not exactly 400 bytes are the end of a packet. */
    if(len < 400)
    {
        sasl_packet(sess);
        sess->buflen = 0;
        if (sess->buf != NULL)
          free(sess->buf);
        sess->buf = sess->p = NULL;
    }
}

static void
nickserv_db_cleanup(UNUSED_ARG(void* extra))
{
    unreg_del_user_func(nickserv_remove_user, NULL);
    unreg_sasl_input_func(handle_sasl_input, NULL);
    userList_clean(&curr_helpers);
    policer_params_delete(nickserv_conf.auth_policer_params);
    dict_delete(nickserv_handle_dict);
    dict_delete(nickserv_nick_dict);
    dict_delete(nickserv_opt_dict);
    dict_delete(nickserv_allow_auth_dict);
    dict_delete(nickserv_email_dict);
    dict_delete(nickserv_id_dict);
    dict_delete(nickserv_conf.weak_password_dict);
    free(auth_func_list);
    free(auth_func_list_extra);
    free(unreg_func_list);
    free(unreg_func_list_extra);
    free(rf_list);
    free(rf_list_extra);
    free(allowauth_func_list);
    free(allowauth_func_list_extra);
    free(handle_merge_func_list);
    free(handle_merge_func_list_extra);
    free(failpw_func_list);
    free(failpw_func_list_extra);
    if (nickserv_conf.valid_handle_regex_set)
        regfree(&nickserv_conf.valid_handle_regex);
    if (nickserv_conf.valid_nick_regex_set)
        regfree(&nickserv_conf.valid_nick_regex);
}

void handle_loc_auth_oper(struct userNode *user, UNUSED_ARG(struct handle_info *old_handle), UNUSED_ARG(void *extra)) {
    char *privv[MAXNUMPARAMS];
    int privc, i;

    if (!*nickserv_conf.auto_oper || !user->handle_info)
        return;

    if (!IsOper(user)) {
        if (*nickserv_conf.auto_admin && user->handle_info->opserv_level >= opserv_conf_admin_level()) {
            if (nickserv_conf.auto_admin_privs[0]) {
                irc_raw_privs(user, nickserv_conf.auto_admin_privs);
                privc = split_line(strdup(nickserv_conf.auto_admin_privs), false, MAXNUMPARAMS, privv);
                for (i = 0; i < privc; i++) {
                    client_modify_priv_by_name(user, privv[i], 1);
                }
            }
            irc_umode(user, nickserv_conf.auto_admin);
            irc_sno(0x1, "%s (%s@%s) is now an IRC Administrator",
                    user->nick, user->ident, user->hostname);
            send_message(user, nickserv, "NSMSG_AUTO_OPER_ADMIN");
        } else if (*nickserv_conf.auto_oper && user->handle_info->opserv_level) {
            if (nickserv_conf.auto_oper_privs[0]) {
                irc_raw_privs(user, nickserv_conf.auto_oper_privs);
                privc = split_line(strdup(nickserv_conf.auto_oper_privs), false, MAXNUMPARAMS, privv);
                for (i = 0; i < privc; i++) {
                    client_modify_priv_by_name(user, privv[i], 1);
                }
            }
            irc_umode(user, nickserv_conf.auto_oper);
            irc_sno(0x1, "%s (%s@%s) is now an IRC Operator",
                    user->nick, user->ident, user->hostname);
            send_message(user, nickserv, "NSMSG_AUTO_OPER");
        }
    }
}

void
init_nickserv(const char *nick)
{
    struct chanNode *chan;
    unsigned int i;
    NS_LOG = log_register_type("NickServ", "file:nickserv.log");
    reg_new_user_func(new_user_event, NULL);
    reg_nick_change_func(handle_nick_change, NULL);
    reg_del_user_func(nickserv_remove_user, NULL);
    reg_account_func(handle_account);
    reg_auth_func(handle_loc_auth_oper, NULL);
    reg_sasl_input_func(handle_sasl_input, NULL);

    /* set up handle_inverse_flags */
    memset(handle_inverse_flags, 0, sizeof(handle_inverse_flags));
    for (i=0; handle_flags[i]; i++) {
        handle_inverse_flags[(unsigned char)handle_flags[i]] = i + 1;
        flag_access_levels[i] = 0;
        /* ensure flag I requires a minimum of 999 if not set in the config */
        if ((unsigned char)handle_flags[i] == 'I')
            flag_access_levels[i] = 999;
    }

    conf_register_reload(nickserv_conf_read);
    nickserv_opt_dict = dict_new();
    nickserv_email_dict = dict_new();

    dict_set_free_keys(nickserv_email_dict, free);
    dict_set_free_data(nickserv_email_dict, nickserv_free_email_addr);

    nickserv_module = module_register("NickServ", NS_LOG, "nickserv.help", NULL);
/* Removed qualified_host as default requirement for AUTH, REGISTER, PASS, etc. nets 
 * can enable it per command  using modcmd. (its a shitty default IMO, and now in 1.3 
 * a big pain to disable  since its nolonger in the config file. )   -Rubin
 */
    modcmd_register(nickserv_module, "AUTH", cmd_auth, 2, MODCMD_KEEP_BOUND, "flags", "+loghostmask", NULL);
    nickserv_define_func("ALLOWAUTH", cmd_allowauth, 0, 1, 0);
    nickserv_define_func("REGISTER", cmd_register, -1, 0, 0);
    nickserv_define_func("OREGISTER", cmd_oregister, 0, 1, 0);
    nickserv_define_func("UNREGISTER", cmd_unregister, -1, 1, 0);
    nickserv_define_func("OUNREGISTER", cmd_ounregister, 0, 1, 0);
    nickserv_define_func("ADDMASK", cmd_addmask, -1, 1, 0);
    nickserv_define_func("OADDMASK", cmd_oaddmask, 0, 1, 0);
    nickserv_define_func("DELMASK", cmd_delmask, -1, 1, 0);
    nickserv_define_func("ODELMASK", cmd_odelmask, 0, 1, 0);
    nickserv_define_func("ADDCERTFP", cmd_addsslfp, -1, 1, 0);
    nickserv_define_func("OADDCERTFP", cmd_oaddsslfp, 0, 1, 0);
    nickserv_define_func("DELCERTFP", cmd_delsslfp, -1, 1, 0);
    nickserv_define_func("ODELCERTFP", cmd_odelsslfp, 0, 1, 0);
    nickserv_define_func("PASS", cmd_pass, -1, 1, 0);
    nickserv_define_func("SET", cmd_set, -1, 1, 0);
    nickserv_define_func("OSET", cmd_oset, 0, 1, 0);
    nickserv_define_func("ACCOUNTINFO", cmd_handleinfo, -1, 0, 0);
    nickserv_define_func("USERINFO", cmd_userinfo, -1, 1, 0);
    nickserv_define_func("RENAME", cmd_rename_handle, -1, 1, 0);
    nickserv_define_func("VACATION", cmd_vacation, -1, 1, 0);
    nickserv_define_func("MERGE", cmd_merge, 750, 1, 0);
    if (!nickserv_conf.disable_nicks) {
	/* nick management commands */
	nickserv_define_func("REGNICK", cmd_regnick, -1, 1, 0);
	nickserv_define_func("OREGNICK", cmd_oregnick, 0, 1, 0);
	nickserv_define_func("UNREGNICK", cmd_unregnick, -1, 1, 0);
	nickserv_define_func("OUNREGNICK", cmd_ounregnick, 0, 1, 0);
	nickserv_define_func("NICKINFO", cmd_nickinfo, -1, 1, 0);
        nickserv_define_func("RECLAIM", cmd_reclaim, -1, 1, 0);
    }
    if (nickserv_conf.email_enabled) {
        nickserv_define_func("AUTHCOOKIE", cmd_authcookie, -1, 0, 0);
        nickserv_define_func("RESETPASS", cmd_resetpass, -1, 0, 0);
        nickserv_define_func("COOKIE", cmd_cookie, -1, 0, 0);
        nickserv_define_func("DELCOOKIE", cmd_delcookie, -1, 1, 0);
        nickserv_define_func("ODELCOOKIE", cmd_odelcookie, 0, 1, 0);
        dict_insert(nickserv_opt_dict, "EMAIL", opt_email);
    }
    nickserv_define_func("GHOST", cmd_ghost, -1, 1, 0);
    /* ignore commands */
    nickserv_define_func("ADDIGNORE", cmd_addignore, -1, 1, 0);
    nickserv_define_func("OADDIGNORE", cmd_oaddignore, 0, 1, 0);
    nickserv_define_func("DELIGNORE", cmd_delignore, -1, 1, 0);
    nickserv_define_func("ODELIGNORE", cmd_odelignore, 0, 1, 0);
    /* miscellaneous commands */
    nickserv_define_func("STATUS", cmd_status, -1, 0, 0);
    nickserv_define_func("SEARCH", cmd_search, 100, 1, 0);
    nickserv_define_func("SEARCH UNREGISTER", NULL, 800, 1, 0);
    nickserv_define_func("MERGEDB", cmd_mergedb, 999, 1, 0);
    nickserv_define_func("CHECKPASS", cmd_checkpass, 601, 1, 0);
    nickserv_define_func("CHECKEMAIL", cmd_checkemail, 0, 1, 0);
    /* other options */
    dict_insert(nickserv_opt_dict, "INFO", opt_info);
    dict_insert(nickserv_opt_dict, "WIDTH", opt_width);
    dict_insert(nickserv_opt_dict, "TABLEWIDTH", opt_tablewidth);
    dict_insert(nickserv_opt_dict, "COLOR", opt_color);
    dict_insert(nickserv_opt_dict, "PRIVMSG", opt_privmsg);
    dict_insert(nickserv_opt_dict, "AUTOHIDE", opt_autohide);
    dict_insert(nickserv_opt_dict, "STYLE", opt_style); 
    dict_insert(nickserv_opt_dict, "PASS", opt_password);
    dict_insert(nickserv_opt_dict, "PASSWORD", opt_password);
    dict_insert(nickserv_opt_dict, "FLAGS", opt_flags);
    dict_insert(nickserv_opt_dict, "ACCESS", opt_level);
    dict_insert(nickserv_opt_dict, "LEVEL", opt_level);
    dict_insert(nickserv_opt_dict, "EPITHET", opt_epithet);
    dict_insert(nickserv_opt_dict, "NOTE", opt_note);
    if (nickserv_conf.titlehost_suffix) {
        dict_insert(nickserv_opt_dict, "TITLE", opt_title);
        dict_insert(nickserv_opt_dict, "FAKEHOST", opt_fakehost);
    }
    dict_insert(nickserv_opt_dict, "ANNOUNCEMENTS", opt_announcements);
    dict_insert(nickserv_opt_dict, "MAXLOGINS", opt_maxlogins);
    dict_insert(nickserv_opt_dict, "ADVANCED", opt_advanced);
    dict_insert(nickserv_opt_dict, "LANGUAGE", opt_language);
    dict_insert(nickserv_opt_dict, "KARMA", opt_karma);

    nickserv_handle_dict = dict_new();
    dict_set_free_keys(nickserv_handle_dict, free);
    dict_set_free_data(nickserv_handle_dict, free_handle_info);

    nickserv_id_dict = dict_new();
    dict_set_free_keys(nickserv_id_dict, free);

    nickserv_nick_dict = dict_new();
    dict_set_free_data(nickserv_nick_dict, free);

    nickserv_allow_auth_dict = dict_new();

    userList_init(&curr_helpers);

    if (nick) {
        const char *modes = conf_get_data("services/nickserv/modes", RECDB_QSTRING);
        nickserv = AddLocalUser(nick, nick, NULL, "Nick Services", modes);
        nickserv_service = service_register(nickserv);
    }
    saxdb_register("NickServ", nickserv_saxdb_read, nickserv_saxdb_write);
    reg_exit_func(nickserv_db_cleanup, NULL);
    if(nickserv_conf.handle_expire_frequency)
        timeq_add(now + nickserv_conf.handle_expire_frequency, expire_handles, NULL);
    if(nickserv_conf.nick_expire_frequency && nickserv_conf.expire_nicks)
        timeq_add(now + nickserv_conf.nick_expire_frequency, expire_nicks, NULL);

    if(autojoin_channels && nickserv) {
        for (i = 0; i < autojoin_channels->used; i++) {
            chan = AddChannel(autojoin_channels->list[i], now, "+nt", NULL, NULL);
            AddChannelUser(nickserv, chan)->modes |= MODE_CHANOP;
        }
    }

#ifdef WITH_LDAP
    ldap_do_init(nickserv_conf);
#endif

    message_register_table(msgtab);
}
