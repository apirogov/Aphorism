#!/usr/bin/env ruby
#Initialize Database for Aphorism
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

class User < ActiveRecord::Base
  #shortcut for getting a user by name (instead of by id)
  def self.getUserWithNick(name)
    result = self.find(:all,:conditions => "nickname = \"#{name}\"").first
    p result
    result
  end
end

#create folder if it dies not exist
require 'fileutils'
FileUtils.mkdir("db") if File.exists?("db")==false

#connect to database
ActiveRecord::Base.establish_connection(:adapter=>:sqlite3, :database=>"db/data.sqlite3")

#new database? create empty tables and stuff...
if File.exists?("db/data.sqlite3")==false
  ActiveRecord::Schema.define do
    create_table :users do |t|
      t.column :nickname, :string #nickname (login name)
      t.column :pwdhash, :string  #SHA256 of password (for server authentication)
      t.column :pubkey, :string   #public key (JSON string)
      t.column :cprivkey, :string #aes crypted private RSA key (AES crypted JSON string)
      t.column :clist, :string    #contact list with nicks and corresponding authorization states
                                  #as JSON -> {"nicks": ["a","b","c"], "authstate": ["t","p","f"]}
                                  #t=true f=false p=pending (request sent)
      t.column :msgqueue, :string #contains the messages from other contacts awaiting delivery
                                  #as JSON -> {"messages": [<message1JSONstring>, ...]}
    end
  end
end


