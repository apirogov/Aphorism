#!/usr/bin/env ruby
#Wrappers for openssl AES and RSA stuff etc.
#Copyright (C) 2010 Anton Pirogov
#Licensed under GPLv3 or later

require 'openssl'
require 'base64'

#AES compatible to Gibberish-AES (OpenSSL aes-256-cbc)
#see namespace GibberishAES in the client part
module AES
  def AES.enc(plain, password)
    #generate 8 byte random salt
    salt = 8.times.inject(""){|str| str += rand(256).chr}

    #init openssl aes
    c = OpenSSL::Cipher::Cipher.new('aes-256-cbc').encrypt

    #set key and IV from pwd and salt
    c.pkcs5_keyivgen(password, salt, 1)

    #pipe data
    cipher = c.update(plain)
    cipher << c.final

    #prepare output
    magicbytes = [83, 97, 108, 116, 101, 100, 95, 95].map{|n| n.chr}.join
    result = magicbytes + salt + cipher

    return Base64.encode64(result)
  end

  def AES.dec(cipher, password)
    #split magic, salt and data
    cipher=Base64.decode64(cipher)
    salt     = cipher[8..15]
    data     = cipher[16..-1]

    #init openssl aes
    c = OpenSSL::Cipher::Cipher.new('aes-256-cbc').decrypt

    #set key and IV with pwd and salt
    c.pkcs5_keyivgen(password, salt, 1)

    #pipe data
    result = c.update(data)
    result << c.final

    return result
  end
end

#Equivalent to RSA in crypt.js -> compatible (a key is a JSON with the numbers in hex -> {"e": "ffa3452356fa", ...}
#instead of JSON key is stored in hash
module RSA
  ############ PRIVATE METHODS NOT TO BE USED OUTSIDE ############

  #key = {:e => "hexnumber", :n => "hexnumber"}
  #insert such a key into a OpenSSL PKey
  def RSA.set_rsa_key(hash)
    rsa = OpenSSL::PKey::RSA.new(1024)
    hash.each_pair{|key, value|
      if key!="coeff" #called iqmp here (coeff is the name in the js counterpart)
        rsa.method(key+"=").call(value.to_i(16))
      else
        rsa.iqmp = value.to_i(16)
      end
    }
    return rsa
  end

  #string with binary data -> hex encoded -> each byte becomes a 2 digit hex number (0-255)
  def RSA.bin2hex(bin)
    hex = bin.split(//)
    hex.map!{ |n|        #for each char:
      x=n.ord.to_s(16)
      x="0"+x if x.length<2 #for 1-digit chars -> prepend leading 0 = "f" -> "0f"
      x
    }
    hex = hex.join
    return hex
  end

  #the reverse.. a little more tricky
  def RSA.hex2bin(hex)
    data, tmp = "", ""
    hex = hex.split(//)
    hex.each_with_index{ |n,i|
      if i%2==0
        tmp = n
      else
        data += (tmp+n).to_i(16).chr
      end
    }
    return data
  end

  ################### ENCRYPTION ######################

  #encrypt with public key
  def RSA.encrypt(text, key)
    rsa = set_rsa_key(key)            #init key and stuff
    cipher = rsa.public_encrypt(text) #encrypt
    cipher = bin2hex(cipher)          #convert binary data to hex
    return cipher
  end

  #decrypt with private key
  def RSA.decrypt(cipher, key)
    rsa = set_rsa_key(key)            #init key and stuff
    data = hex2bin(cipher)            #convert from hex to binary again
    return rsa.private_decrypt(data)  #decrypt
  end

  #encrypt with private key
  def RSA.sign(text, key)
    rsa = set_rsa_key(key)            #init key and stuff
    cipher = rsa.private_encrypt(text) #encrypt
    cipher = bin2hex(cipher)          #convert binary data to hex
    return cipher
  end

  #decrypt with public key
  def RSA.verify(cipher, key)
    rsa = set_rsa_key(key)            #init key and stuff
    data = hex2bin(cipher)            #convert from hex to binary again
    return rsa.public_decrypt(data)   #decrypt
  end

  ############# KEY GENERATION ##################

  #generate key of given size, returns json with all rsa numbers as hex strings
  def RSA.gen_keys(bits=1024)
    key = OpenSSL::PKey::RSA.new(bits)
    keyhash = Hash.new
    keyhash["e"] = key.e.to_s(16).downcase
    keyhash["n"] = key.n.to_s(16).downcase
    keyhash["p"] = key.p.to_s(16).downcase
    keyhash["q"] = key.q.to_s(16).downcase
    keyhash["d"] = key.d.to_s(16).downcase
    keyhash["dmp1"] = key.dmp1.to_s(16).downcase
    keyhash["dmq1"] = key.dmq1.to_s(16).downcase
    keyhash["coeff"] = key.iqmp.to_s(16).downcase
    return keyhash
  end

  #return just public data from key to store seperately as public key
  def RSA.get_public_key(privkey)
    return {"e" => privkey["e"], "n" => privkey["n"]}
  end
end
