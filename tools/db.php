<pre>
<?php
/*
 This is a php function & demo util which parses the x3.db and x3.conf files for use in web programs.

 Written by Jobe:
<Jobe> reads in the DB, parses it then print_r's it
<Jobe> if it comes across a syntax it doesnt know it stops parsing and puts the remaining data, all of it in ['parserror'] in whatever array its working in
*/

$conf['dbfile'] = "x3.db";

$dh = fopen($conf['dbfile'], "r");

$contents = fread($dh, filesize($conf['dbfile']));

fclose($dh);

function parse_data ($data = "") {
    static $passback = "";
    $working = $data;
    $return = array();
    $loop = true;

    if ( $data != "" ) {
        while ( $loop ) {
            if ( preg_match("/^\s*\/\/([^\n\r]*)[\n\r]*(.*)\$/s", $working, $matches) ) {
                /* ignore // comments */
                $working = $matches[2];
            } else if ( preg_match("/^\s*#([^\n\r]*)[\n\r]*(.*)\$/s", $working, $matches) ) {
                /* ignore # comments */
                $working = $matches[2];
            } else if ( preg_match("/^\s*\/\*(.*?)\*\/\s*(.*)\$/s", $working, $matches) ) {
                // ignore /* */ comments
                $working = $matches[2];
            } else if ( preg_match("/^\s*\}\s*;\s*(.*)\$/s", $working, $matches) ) {
                /* section end */
                $passback = $matches[1];
                $loop = false;
            } else if ( preg_match("/^\s*((\"(((\\\\\")|[^\"])+)\")|([^\s]+))\s*\{\s*(.*)\$/s", $working, $matches) ) {
                /* section start (name quoted) */
                if ( $matches[3] != "" ) {
                    $return[strtolower($matches[3])] = parse_data($matches[7]);
                } else {
                    $return[strtolower($matches[1])] = parse_data($matches[7]);
                }
                $working = $passback;
            } else if ( preg_match("/^\s*((\"(((\\\\\")|[^\"])+)\")|([^\s]+))\s*\(\s*((((\"(((\\\\\")|[^\"])+)\")|([^\s,]+))\s*(,\s*((\"(((\\\\\")|[^\"])+)\")|([^\s,]+))\s*)*)?)\s*\)\s*;\s*(.*)\$/s", $working, $matches) ) {
                /* array */
                $arraycontents = $matches[7];
                $array = array();
                while ( preg_match("/[^\s]+/", $arraycontents) ) {
                    preg_match("/^\s*,?\s*((\"(((\\\\\")|[^\"])+)\")|([^\s,]+))\s*(.*)/s", $arraycontents, $arraymatches);
                    if ( $arraymatches[3] != "" ) {
                        $array[] = $arraymatches[3];
                    } else {
                        $array[] = $arraymatches[1];
                    }
                    $arraycontents = $arraymatches[7];
                }
                if ( $matches[3] != "" ) {
                    $return[strtolower($matches[3])] = $array;
                } else {
                    $return[strtolower($matches[1])] = $array;
                }
                $working = $matches[22];
            } else if ( preg_match("/^\s*((\"(((\\\\\")|[^\"])+)\")|([^\s,]+))\s*(((\"(((\\\\\")|[^\"])+)\")|([^\s,]+)))?\s*;\s*(.*)\$/s", $working, $matches) ) {
                /* name value pair */
                if ( $matches[3] != "" ) {
                    $key = strtolower($matches[3]);
                } else {
                    $key = strtolower($matches[1]);
                }
                if ( $matches[7] != "" ) {
                    if ( $matches[10] != "" ) {
                        $val = $matches[10];
                    } else {
                        $val = $matches[7];
                    }
                    if ( isset($return[$key]) ) {
                        if ( !is_array($return[$key]) ) {
                            $temp = $return[$key];
                            unset($return[$key]);
                            $return[$key][] = $temp;
                            $return[$key][] = $val;
                        } else {
                            $return[$key][] = $val;
                        }
                    } else {
                        $return[$key] = $val;
                    }
                } else {
                    $return[$key] = array();
                }
                $working = $matches[14];
            } else {
                if ( $working != "" ) {
                    $return['parseerror'] = $working;
                }
                $passback = "";
                $loop = false;
            }
        }
    }

    return $return;
}

$db = parse_data($contents);

print_r($db);

?>
</pre>

