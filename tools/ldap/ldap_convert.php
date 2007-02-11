#!/usr/bin/php
<?
/*
 *   This script is used to export users from x3.db to an ldap server
 *   when initially converting to x3's ldap based authentication.
 * 
 *   Its expected you would modify and well-test this before running it on 
 *   a production database. Use at your own risk!
 *  
 *   Edit the variables below first..
 *
 */
/* -------------------------------------------- */;
/* CONFIGURATION */
/* -------------------------------------------- */;

$db = "/home/you/x3/x3.db";
$ldap_server = "localhost";
$ldap_bind = "cn=admin,dc=afternet,dc=org";
$ldap_pass = "yourpassword";
$ldap_add = "ou=Users,dc=afternet,dc=org"; /* excludes the uid= part on purpose, dont add in */

/* -------------------------------------------- */;

echo "------------------------------------------\n";
echo "X3 to LDAP dump script\n";
echo "Copyright (C) 2007 evilnet development\n";
echo "------------------------------------------\n\n";

if (!extension_loaded('ldap'))
    die("PHP Extension LDAP MUST be loaded before using this script.\n");

$handle=fopen($db, r);
$ns = 0;
$bs = 0;
$add = 0;
$parse = 0;

if ($handle) {
    echo "Connecting to ldap server\n";
    $ds=ldap_connect($ldap_server);

    if (!$ds)
        die("Couldnt connect to ldap server\n");

    echo "Switching to ldap protocol 3\n";
    ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);

    echo "Binding to ldap server\n";
    $r=ldap_bind($ds, $ldap_bind, $ldap_pass);
    if (!$r)
        die("LDAP bind error - ". ldap_error($ds) ."\n");

    echo "Attempting to read $db\n";
    while (!feof($handle)) {
        $line = fgets($handle, 4096);
        $line = trim($line);
        $gotpass = 0;
        $gotemail = 0;
        $user = NULL;
        $pass = NULL;
        $email = NULL;
        if (($line == "\"NickServ\" {") && ($bs == 0)) {
	    echo "SSTARTT\n";
            $ns = 1;
            continue;
        }

        if ($line == "\"ChanServ\" {") {
	    $bs = 1;
            $ns = 0;
	}

        if ($ns == 1) {
            $parse++;
            $space = " ";
            $exp = explode($space, $line);
            $i = sizeof($exp);
            $i--;
            while ($exp[$i] != NULL) {
                if (($exp[$i] == "\"passwd\"") && ($gotpass == 0)) {
                    $pass = $exp[$i+1];
                    $gotpass = 1;
                }

                if (($exp[$i] == "\"email_addr\"") && ($gotemail == 0)) {
                    $email = $exp[$i+1];
                    $gotemail = 1;
                }
                $i--;
            }

            $user = $exp[0];

            $user = trim($user, "\";");
            $pass = trim($pass, "\";");
            $email = trim($email, "\";");
            if ($user && $pass && $email && ($user != "}")) {
                unset($info);

                $info["objectclass"][] = "top";
                $info["objectclass"][] = "inetOrgAnonAccount";
                $info["uid"]=$user;
                $info["mail"]=$email;
		if ($pass[0] == "$") {
			$info["userPassword"] = "";
			echo "ALERT: $user ADDED WITH NO PASSWORD (old crypt style)\n";
		} else
	                $info["userPassword"]='{MD5}'.base64_encode(pack('H*',$pass));

                $r=@ldap_add($ds, "uid=".$user.",$ldap_add", $info);
                if ($r) {
                    $add++;
                    echo "Added $user (email: $email) (pass: $pass)\n";
                } else
                    echo "Failed adding $user (email: $email) (pass: $pass) - ". ldap_error($ds) ."\n";

            } else if (!$user || !$pass || !$email) {
                if (!$user && !$pass && !$email)
                    continue; /* misc bits after entries */

                if (($user == "}") && !$pass && !$email)
                    continue; /* misc bits after entries */

                echo "Missing fields from $db (User: $user Pass: $pass Email: $email)\n";
            }

        }
    }
} else 
  die("Couldnt read $db\n");

echo "Disconnecting from ldap server\n";
ldap_close($ds);
$parse--;
$parse--;
echo "Processed $parse accounts.\n";
echo "Added $add accounts to the ldap server\n";

?>
