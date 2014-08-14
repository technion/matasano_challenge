#!/usr/bin/env ruby
#technion@lolware.net

f = File.read('8.txt');
#Let's work with hex


blocks = [];
f = f.gsub(/[\r\n\t]/, ''); #Strip the whitespace

(0..f.length).step(32) { |n|
    oneblock = f[n..n+31];
    if blocks.include?(oneblock) 
        puts "Duplicate detected: #{oneblock}";
    else
        blocks.push(oneblock);
    end

}

