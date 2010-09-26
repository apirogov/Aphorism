#!/usr/bin/env ruby
#Sinatra web instant messenger app
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

require 'rubygems' if RUBY_VERSION < "1.9"

#stuff relating to webserver
require 'sinatra'
#Sinatra 1.0 on ruby 1.9.2 fixes
enable :run
set :public, Dir.pwd+'/public'
set :views, Dir.pwd+'/views'

require 'haml'
require 'sass'

require 'digest/sha2'     #SHA256 for hashing
require 'json'            #to pass objects to client and back... and as db storage format

#DataMapper
require 'dm-core'
require 'dm-migrations'

#Program modules
require_relative 'antispam'     #captcha generation
require_relative 'dbinterface'  #inits/loads database, gives functions for accessing
require_relative 'im_funcs'  #everything running after authentication (helper methods)
require_relative 'login_funcs'      #Public stuff, login+authentication, secure route

#establish the main page routes

get '/stylesheet.css' do
  response['Content-Type'] = 'text/css; charset=utf-8'  #set header to be recognized as css
  sass :stylesheet                                      #render sass file to css
end

get '/' do
  haml :index
end

