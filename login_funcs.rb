#!/usr/bin/env ruby
#Login funcs
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

#TODO: jquery-ui stuff on clientside!

$sessions = Hash.new  #session hash storing IP, sessionid, current session pwd and idle time
$captchas = Hash.new  #stores base64 png pic and text

#random hex token generator for example for sessionid
def gen_random_hex(len)
  (1..len).inject(""){|str| str += rand(16).to_s(16)}
end

#its secure enough...
def gen_sessionid
  gen_random_hex(16)
end

#input: nick
#output: hash for response
def start_session(nick)
  usr = User.first(:nickname=>params[:nickname])
  p User.all
  if usr != nil
    sid = gen_sessionid

    #associate nick with sid & IP & communication password
    $sessions[nick] = {:ip=>@env['REMOTE_ADDR'], :sid=> sid, :lastrequest=> Time.now.to_i}

    #return JSON with sessionid
    return {:sid => sid}
  end
  return 'error'
end

#check session validity
def check_session
  #get nick and session id
  nick = params[:nickname]
  sessionid = params[:sessionid]

  #compare nick, sid and ip with running sessions
  return false if $sessions[nick]==nil
  if $sessions[nick][:ip] == @env['REMOTE_ADDR'] && $sessions[nick][:sid] == sessionid
    #valid session access -> set "last access time"
    $sessions[nick][:lastrequest] = Time.now.to_i
    return true
  end

  return false
end

####### Routes
get '/captcha' do
  response['Content-Type'] = 'application/json; charset=utf-8'
  cap = AntiSpam.generate_picture
  capid = gen_random_hex(8)
  $captchas[capid] = cap

  return JSON.generate({:blob => cap[0], :id => capid})
end

get '/check_nickname' do
  if User.first(:nickname=>params[:name])==nil
    res='free'
  else
    res='taken'
  end
  res
end

get '/show_login_form' do
  haml :loginform, :layout => false
end

#DEBUG: to test whether logged in or not  (provide nick and sessionid over GET!)
get '/check' do
  check_session.to_s
end

####### LEVEL 2 routes -> login process
post '/login' do
  #check user password hash
  usr = User.first(:nickname => params[:nickname])

  if usr.pwdhash == Digest::SHA256.hexdigest(params[:password]) #success => return sessionid
    ret = start_session(params[:nickname])
    ret = JSON.generate(ret)  #hash -> json

    broadcast_state(params[:nickname],'online') #tell his online buddies hes online too
  else
    ret = 'fail'  #incorrect password
  end

  ret
end

post '/register' do
  if User.first(:nickname => params[:nickname]) == nil #nickname is free
    if $captchas[params[:capid]][1] == params[:capval] #captcha solved
      $captchas.delete(:capid)    #remove that captcha

      #create user in the database
      usr = User.new
      usr.nickname = params[:nickname]
      usr.pwdhash = Digest::SHA256.hexdigest(params[:password])
      usr.save

      #start session...
      ret = start_session(params[:nickname])
      puts ret
      ret = JSON.generate(ret)  #hash -> json

      broadcast_state(params[:nickname],'online') #tell his online buddies hes online too
    else
      ret = "captcha failed!"
    end
  else
    ret = 'user exists!'
  end

  ret
end

get '/logout' do
  if check_session #check whether valid logged in
    $sessions.delete(params[:nickname]) #remove session associacion

    broadcast_state(params[:nickname],'offline')  #tell all his online contacts he's off

    ret = 'ok'
  else
    ret = 'error'
  end
  ret
end

#common protocol: input = JSON as POST parameter 'data'
#this JSON has to contain the string node cmd including the request
#all other nodes depend on the command itself
#the response must contain the string node response giving bool of success and 'report' with error message on fail
#the other nodes depend on the previous request
post '/imcommand' do
  if check_session  #check if logged in
    data = JSON.parse(params[:data])               #make hash from json data

    ret = JSON.generate(evaluate_command(data))          #get JSON object with response
    ret                                                   #let it be returned
  end
end

