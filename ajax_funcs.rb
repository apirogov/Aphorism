#!/usr/bin/env ruby
#AJAX Funcs
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

#TODO: jquery-ui stuff on clientside!

#stores the running sessions
$sessions = Hash.new
$semaphore = Mutex.new    #lock for session data for threads

#start thread looking for long idle sessions to kill them! (paused when checking sessions)
sessionkiller = Thread.new {
  while true
    now = Time.now
    #delete sessions without requests for more than 1 min (lock sessions var)

    $semaphore.synchronize do
      $sessions.delete_if{|nick,session| (now-session[:lastrequest]) > 60 }
    end

    sleep 5 #wait 5 seconds
  end
}


def gen_random_hex(len)
  (1..len).inject(""){|str| str += rand(16).to_s(16)}
end

#its secure enough...
def gen_sessionid
  gen_random_hex(16)
end

#random session AES 256 bit password for communication
def gen_communication_pwd
  gen_random_hex(32)
end

#input: nick
#output: hash for response
def start_session(nick)
  usr = User.getUserWithNick(params[:nickname])
  if usr != nil
    sid = gen_sessionid
    scpwd = gen_communication_pwd
    #encrypt with public key of user
    enc_scpwd = RSA.encrypt(scpwd, JSON.parse(usr.pubkey))

    #associate nick with sid & IP & communication password (thread safely)
    $semaphore.synchronize do
      $sessions[nick] = {:ip=>@env['REMOTE_ADDR'], :sid=> sid, :scpwd=> scpwd, :lastrequest=> Time.now.to_i}
    end

    #return JSON with sessionid and password for encrypted communication
    return {:sid => sid, :enc_scpwd => enc_scpwd}
  end
  return 'error'
end

#check session validity
def check_sessionid
  #get nick and session id
  nick = params[:nickname]
  sessionid = params[:sessionid]

  $semaphore.synchronize do

    #compare nick, sid and ip with running sessions
    return false if $sessions[nick]==nil
    if $sessions[nick][:ip] == @env['REMOTE_ADDR'] && $sessions[nick][:sid] == sessionid
      #valid session access -> set "last access time"
      $sessions[nick][:lastrequest] = Time.now.to_i
      return true
    end

  end

  return false
end

####### LEVEL 1 routes -> NO authentication, GET
get '/captcha' do
  response['Content-Type'] = 'application/json; charset=utf-8'
  AntiSpam.generate_picture
end

get '/check_nickname' do
  if User.getUserWithNick(params[:name])==nil
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
  check_sessionid.to_s
end

####### LEVEL 2 routes -> login process
post '/login' do
  #check user password hash
  usr = User.getUserWithNick(params[:nickname])

  if usr.pwdhash == params[:password] #success => return sessionid and crypt password for the session
    ret = start_session(params[:nickname])
    ret[:cprivkey] = usr.cprivkey
    ret = JSON.generate(ret)  #hash -> json

    broadcast_state(params[:nickname],'online') #tell his online buddies hes online too
  else
    ret = 'fail'  #incorrect password
  end

  ret
end

post '/register' do
  #create user in the database
  if User.getUserWithNick(params[:nickname]) == nil #just to make sure...
    usr = User.new
    usr.nickname = params[:nickname]
    usr.pwdhash = params[:password]
    usr.pubkey = params[:pubkey]
    usr.cprivkey = params[:cprivkey]
    usr.clist = "{\"nicks\": [], \"authstate\": []}"  #empty Contact List JSON
    usr.msgqueue = "{\"messages\": []}" #empty Message Queue JSON
    usr.save

    #start session...
    ret = start_session(params[:nickname])
    ret = JSON.generate(ret)  #hash -> json

    broadcast_state(params[:nickname],'online') #tell his online buddies hes online too
  else
    ret = 'error'
  end

  ret
end

get '/logout' do
  if check_sessionid #check whether valid logged in
    $semaphore.synchronize do
      $sessions.delete(params[:nickname]) #remove session associacion
    end

    broadcast_state(params[:nickname],'offline')  #tell all his online contacts he's off

    ret = 'ok'
  else
    ret = 'error'
  end
  ret
end

###### LEVEL 4 route -> ENCRYPTED
############ the most important route #################
#common protocol of secure: input = AEScrypted JSON as POST parameter 'data'
#this JSON has to contain the string node cmd including the request
#all other nodes depend on the command itself
#the response must contain the string node response giving bool of success and 'report' with error message on fail
#the other nodes depend on the previous request
post '/secure' do
  if check_sessionid  #check if logged in
    scpwd = $sessions[params[:nickname]][:scpwd]  #get session communication password

    data = AES.dec(params[:data], scpwd)  #decrypt POSTed data
    data = JSON.parse(data)               #make hash from json data

    ret = evaluate_command(data)          #get JSON object with response
    ret = prepare_response(ret)           #encrypt the response

    ret                                   #let it be returned
  end
end

