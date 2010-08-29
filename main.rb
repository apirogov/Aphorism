#!/usr/bin/env ruby
#Sinatra Group Chat app
#Copyright (C) 2010 Anton Pirogov

require 'rubygems' if RUBY_VERSION < "1.9"

#stuff relating to webserver
require 'sinatra'
require 'haml'
require 'sass'

require 'digest/sha2'     #SHA256 for hashing
require 'json'            #to pass objects to client and back... and as db storage format
require 'active_record'   #user database

require 'antispam.rb'     #captcha generation
require 'dbinterface.rb'  #inits/loads database, gives functions for accessing
require 'crypt.rb'        #counterpart to crypt.js

require 'ajax_funcs.rb'   #all AJAX calls... so kinda everything

#establish the main page route (the rest is ajax)
get '/stylesheet.css' do
  response['Content-Type'] = 'text/css; charset=utf-8'  #set header to be recognized as css
  sass :stylesheet                                      #render sass file to css
end

get '/' do
  haml :index
end

