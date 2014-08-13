#!/usr/bin/perl

$ret = `echo 1c0111001f010100061a024b53535009181c | ./chal2.rb`;
chomp($ret);

if ($ret eq '746865206b696420646f6e277420706c6179') {
	print "Successful test\n";
} else {
	print "Failed test and received $ret\n";
}
