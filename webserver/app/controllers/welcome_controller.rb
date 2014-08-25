require 'openssl'
Secretkey = 'slardy'

class WelcomeController < ApplicationController
  def index
    filename = params[:filename]
    signature = params[:signature]
    hmac = OpenSSL::Digest::SHA1.digest(Secretkey + filename).unpack('H*').join
    #render plain: "Invalid signature" unless hmac == signature
    #render plain: filename + hmac
    if slow_equals(hmac, signature)
        @download = "Thank you for downloading file"
    else
        #@download = "YOU CAN HAS NO ACCESS because hmac = #{hmac} and signature = #{signature}"
        return head 500 
    end
  end

  def slow_equals(a, b)
     return false unless a.length == b.length
     (0..a.length-1).each { |n|
         sleep(0.005)
         return false if a[n] != b[n]
     }
     return true
  end
end
