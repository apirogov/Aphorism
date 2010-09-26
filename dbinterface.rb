#!/usr/bin/env ruby
#Initialize Database for Aphorism
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

require 'dm-core'
require 'dm-migrations'

#Absolute path to database
dbpath = "#{Dir.pwd}/test.db"

#DataMapper::Logger.new($stdout, :debug)    #Init logger if you like

#Setup connection to database
DataMapper.setup(:default, "sqlite3://#{dbpath}")   #dm-sqlite-adapter gem required

#initialize models

class User
  include DataMapper::Resource

  property :id, Serial, :key => true
  property :nickname, String    #nickname (login)
  property :pwdhash, String     #SHA256 of password (login)

  has n, :contacts
  has n, :messages
end

class Contact
  include DataMapper::Resource

  belongs_to :user

  property :id, Serial, :key => true
  property :userid, Integer         #contact user id (would be more elegant as association but doesnt work oO)
  property :authgiven, String #authorization state from buddy to contact -> "t"=true, "p"=pending, "f"= false
end

class Message
  include DataMapper::Resource

  belongs_to :user

  property :id, Serial, :key => true
  property :data, String
end

#apply models (validation etc.)
DataMapper.finalize

#if no database file found -> initialize
if File.exists?(dbpath) == false
  DataMapper.auto_migrate!                            #(re)initialize database (destructive!)
end

