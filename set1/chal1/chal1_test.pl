#!/usr/bin/perl

$ret = `echo 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d | ./chal1.rb`;
chomp($ret);

if ($ret eq 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t') {
	print "Successful test\n";
} else {
	print "Failed test and received $ret\n";
}
