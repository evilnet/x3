<?php
/*
 This is a php class & demo util which parses the x3.db and x3.conf files for use in web programs.

 Written by Jobe:
<Jobe> reads in the DB, parses it then print_r's it
<Jobe> if it comes across a syntax it doesnt know it stops parsing and puts the remaining data, all of it in ['parserror'] in whatever array its working in

See bottom of this file for examples of how to use this class
*/

class X3SaxDB {
	public $data;
	private $raw = "";
	
	function X3SaxDB($filename = "") {
		$this->data = Array();
		if ($filename != "") {
			$this->parse($filename);
		}
	}
	
	function parse($raw = "") {
		$temp = Array();
		$temparray = Array();
		$key = "";
		$array = false;
		
		if ($raw != "") {
			$this->raw = $raw;
		}
		
		while ($this->raw != "") {
			if (preg_match("/^[\s\r\n]*#[^\r\n]*[\r\n]+[\s\r\n]*/s", $this->raw, $matches)) {
				// Remove "#<stuff>" comments
				$this->raw = substr($this->raw, strLen($matches[0]));
			} elseif (preg_match("/^[\s\r\n]*\/\/[^\r\n]*[\r\n]+[\s\r\n]*/s", $this->raw, $matches)) {
				// Remove "//<stuff>" comments
				$this->raw = substr($this->raw, strLen($matches[0]));
			} elseif (preg_match("/^\/\*.*?\*\/[\r\n]+[\s\r\n]*/s", $this->raw, $matches)) {
				// Remove "/*<stuff>*/" comments
				$this->raw = substr($this->raw, strLen($matches[0]));
			} elseif (preg_match("/^\}[\s\r\n]*;[\s\r\n]*/s", $this->raw, $matches)) {
				// Block End
				$this->raw = substr($this->raw, strLen($matches[0]));
				break;
			} elseif (preg_match("/^\)[\s\r\n]*;[\s\r\n]*/s", $this->raw, $matches)) {
				// Array End
				$this->raw = substr($this->raw, strLen($matches[0]));
				$temp[$key][] = $temparray;
				$temparray = Array();
				$array = false;
				$key = "";
			} elseif (($key != "") and preg_match("/^\([\s\r\n]*/s", $this->raw, $matches)) {
				// Array Start
				$this->raw = substr($this->raw, strLen($matches[0]));
				$array = true;
			} elseif (($key != "") and preg_match("/^\{[\s\r\n]*/s", $this->raw, $matches)) {
				// Block
				$this->raw = substr($this->raw, strLen($matches[0]));
				$temp[$key][] = $this->parse();
				$key = "";
			} elseif ($array and ($key != "") and preg_match("/^(?:(?:\"(.*?)(?<!\\\\)\")|(?:([^\s]*)))[\s\r\n]*,?[\s\r\n]*/s", $this->raw, $matches)) {
				// Array Value
				$this->raw = substr($this->raw, strLen($matches[0]));
				$val = $matches[1];
				if ($val == "") {
					$val = $matches[2];
				}
				$temparray[] = stripslashes($val);
			} elseif (($key != "") and preg_match("/^(?:=[\s\r\n]*)?(?:(?:\"(.*?)(?<!\\\\)\")|(?:([^\s]*)))[\s\r\n]*;[\s\r\n]*/s", $this->raw, $matches)) {
				// Value
				$this->raw = substr($this->raw, strLen($matches[0]));
				$val = $matches[1];
				if ($val == "") {
					$val = $matches[2];
				}
				$temp[$key][] = stripslashes($val);
				$key = "";
			} elseif (preg_match("/^(?:(?:\"(.+?)(?<!\\\\)\")|(?:([^\s]*)))[\s\r\n]*/s", $this->raw, $matches)) {
				// Key
				$this->raw = substr($this->raw, strLen($matches[0]));
				$key = $matches[1];
				if ($key == "") {
					$key = $matches[2];
				}
			} else {
				// Error
				$temp["parse_error"] = $this->raw;
				$this->raw = "";
				break;
			}
		}
		
		foreach (array_keys($temp) as $key) {
			if (count($temp[$key]) == 1) {
				$temp[$key] = $temp[$key][0];
			}
		}
		
		if ($raw != "") {
			$this->data = $temp;
			return $this->data;
		} else {
			return $temp;
		}
	}
	
	function parsefile($filename = "") {
		
		if ($filename != "") {
			if (file_exists($filename) and is_readable($filename)) {
				$this->raw = file_get_contents($filename);
			}
		}
		
		$this->parse($this->raw);
		return $this->data;
	}
	
	function getval($path, $array = null) {
		$temp = $path;
		$parts = Array();
		$ret = Array();
		
		if (is_null($array)) {
			$ret = $this->data;
		} else {
			$ret = $array;
		}
		
		if (substr($temp, 0, 1) == "/") {
			$temp = substr($temp, 1);
		}
		if (substr($temp, -1) != "/") {
			$temp = $temp . "/";
		}
		
		while ($temp != "") {
			if (preg_match("/(?:(?:\"(.*?)(?<!\\\\)\")|(?:([^\/\r\n\s]*)))\//s", $temp, $matches)) {
				$temp = substr($temp, strLen($matches[0]));
				if ($matches[1] != "") {
					$parts[] = $matches[1];
				} else {
					$parts[] = $matches[2];
				}
			} else {
				$parts['error'] = $temp;
				break;
			}
		}
		
		for ($i=0; $i<count($parts); $i++) {
			$found = false;
			if (!is_array($ret)) { unset($ret); break; }
			foreach (array_keys($ret) as $key) {
				if (strtolower($key) == strtolower($parts[$i])) {
					$parts[$i] = $key;
					$found = true;
				}
			}
			if (!$found) { unset($ret); break; }
			$ret = $ret[$parts[$i]];
			if (($i < count($parts) - 1) and isset($ret[0])) {
				$ret = $ret[0];
			}
		}
		
		return $ret;
	}
}

$x3db = new X3SaxDB();
$data = $x3db->parsefile("data/x3.db");
// $data == copy of $x3db->data
var_dump($x3db->data);
var_dump($x3db->getval("/NickServ/Jobe/email_addr"));
?>
