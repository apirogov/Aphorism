#!/usr/bin/env ruby
#AJAX Funcs
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

#TODO: jquery-ui stuff on clientside! Sign/Verify in crypt.js!
#TODO: Authorization of contacts!

#stores the running sessions
$sessions = Hash.new

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

    #associate nick with sid & IP & communication password
    $sessions[nick] = {:ip=>@env['REMOTE_ADDR'], :sid=> sid, :scpwd=> scpwd}

    #return JSON with sessionid and password for encrypted communication
    return {:sid => sid, :enc_scpwd => enc_scpwd}
  end
  return 'error'
end

#control session
def check_sessionid
  #get nick and session id
  nick = params[:nickname]
  sessionid = params[:sessionid]

  #compare nick, sid and ip with running sessions
  return false if $sessions[nick]==nil
  if $sessions[nick][:ip] == @env['REMOTE_ADDR'] && $sessions[nick][:sid] == sessionid
    return true
  end

  return false
end

####### LEVEL 1 routes -> NO authentication
get '/captcha' do
  response['Content-Type'] = 'application/json; charset=utf-8'
  AntiSpam.generate_picture
end

post '/check_nickname' do
  if User.getUserWithNick(params[:name])==nil
    res='free'
  else
    res='taken'
  end
  res
end

post '/show_login_form' do
  haml :loginform, :layout => false
end

####### LEVEL 2 routes -> login
post '/login' do
  #check user password hash
  usr = User.getUserWithNick(params[:nickname])

  if usr.pwdhash == params[:password] #success => return sessionid and crypt password for the session
    ret = start_session(params[:nickname])
    ret[:cprivkey] = usr.cprivkey
    ret = JSON.generate(ret)  #hash -> json
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
  else
    ret = 'error'
  end

  ret
end

###### LEVEL 3 routes => uncrypted but authenticated
#
get '/logout' do
  if check_sessionid #check whether valid logged in
    $sessions.delete(params[:nickname]) #remove session associacion
    ret = 'ok'
  else
    ret = 'error'
  end
  ret
end

#Delete user from database, remove session
post '/delete_account' do
  #check whether logged in and correct password hash supplied
  usr = User.getUserWithNick(params[:nickname])
  if check_sessionid && params[:password]==usr.pwdhash
    #ok... remove account :(
    User.delete(usr.id) #remove user from database
    $sessions.delete(params[:nickname]) #remove session associacion
    ret='ok'
  else
    #fuck off asshole
    ret='error'
  end
  ret
end

#DEBUG: to test whether logged in or not
get '/check' do
  check_sessionid.to_s
end

###### LEVEL 4 rountes -> ENCRYPTED
#
#here all the fun happens :) this is an interface for the whole functionality...
#input and output are encrypted with the communication password for the session
#the data contains all commands and data as JSON... responses are encrypted JSON objects too

#hash => JSON => AES with session communication password
def prepare_response(hash)
  scpwd = $sessions[params[:nickname]][:scpwd]
  return AES.enc(JSON.generate(hash), scpwd)
end

#evaluates the cmd string and does stuff and gives responses
def evaluate_command(data)
  cmd = data['cmd']
  ownnick = params[:nickname]

  ## for description of the meaning see below (at function definitions)

  if cmd == 'add_contact'
    return add_contact(ownnick, data['nickname'])
  end
  if cmd == 'remove_contact'
    return remove_contact(ownnick, data['nickname'])
  end
  if cmd == 'request_auth'
    return request_auth(ownnick, data['to'], data['message'])
  end
  if cmd == 'grant_auth'
    return grant_auth(ownnick, data['nickname'])
  end
  if cmd == 'withdraw_auth'
    return withdraw_auth(ownnick, data['nickname'])
  end
  if cmd == 'get_pubkey'
    return get_publickey(data['nickname'])
  end
  if cmd == 'pull_clist'
    return pull_clist(ownnick)
  end
  if cmd == 'pull_queue'
    return pull_queue(ownnick)
  end
  if cmd == 'send_im'
    return send_im(ownnick, data['to'], data['message'])
  end

  #for demonstration - secure calculator...
  if cmd == 'calc'
    return calc(data['expression'])
  end

  #########################
  #nothing matched
  return {'response'=>false,'report'=>'Unknown command: '+cmd}
end

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


################### Functions for all request types ###########################

#helper function
def ret_fail(text)
  {'response'=>false, 'report'=> text}
end
#helper function
def ret_success
  {'response'=>true}
end

#demonstration and testing of the crypt tunnel - a calculator
def calc(expression)
  value = 0
  #check that its just numbers and + - * / and () -> no XSS xD
  return {'response'=>'error'} if expr.match(/[^0123456789\+\-\*\/\(\)]/) != nil
  #calculate
  value = eval(expression)
  #return JSON response
  return {'response'=>value}
end

#add a contact to clist.. without authorization
def add_contact(ownnick, person)
  return ret_fail('can not add yourself') if person == ownnick   #you cant add yourself !

  usr = User.getUserWithNick(person)
  return ret_fail('no such user') if usr == nil          #user does not exist !

  ownusr = User.getUserWithNick(ownnick)  #get own record to get the contact list
  clist = JSON.parse(ownusr.clist)
  return ret_fail('already in list') if clist['nicks'].index(person) != nil

  clist['nicks'].push person  #add user to contact list
  clist['authstate'].push 'f' #not authorized yet
  ownusr.clist = JSON.generate(clist) #update record
  ownusr.save

  #TODO: here: authorization request

  return ret_success
end

#client removes contact
def remove_contact(ownnick, person)
  usr = User.getUserWithNick(ownnick)
  return ret_fail('not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)

  clist = JSON.parse(usr.clist) #get the contact list
  index = clist['nicks'].index(person)
  return ret_fail('not in clist') if index == nil  #user not in contact list

  #check whether the other user is given authorization
  otherusr = User.getUserWithNick(person)
  if otherusr != nil      #user exists? if not, doesnt matter...
    hisclist = JSON.parse(otherusr.clist)
    hisindex = hisclist['nicks'].index(ownnick)
    if hisindex != nil    #requesting user is in the clist of the user to be removed?
      auth = hisclist['authstate'][hisindex]
      return ret_fail('withdraw authorization first!') if auth == 't'
    end
  end

  #remove user from list and update database record
  clist['nicks'].delete_at(index)
  clist['authstate'].delete_at(index)
  usr.clist = JSON.generate(clist)
  usr.save

  return ret_success
end

#client requests a public key from a user
def get_publickey(nick)
  usr = User.getUserWithNick(nick)                                #find requested user in database
  return ret_fail('not found') if usr == nil  #user not found
  return {'response'=>true, 'pubkey' => JSON.parse(usr.pubkey)}   #return the pubkey (JSON string -> JSON)
end

#client requests own contact list
def pull_clist(nick)
  usr = User.getUserWithNick(nick)
  return ret_fail('not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)
  clist = JSON.parse(usr.clist) #load JSON string of clist, make hash
  return {'response'=>true, 'clist'=>clist}       #return data
end

#client sends an instant message (authorization request without authorization, other require authorization)
#this method handles auth_requests too... (called by auth_request(...) )
def send_im(fromnick,tonick,message)
  return ret_fail('can not send IM to yourself') if fromnick==tonick      #self-explainatory

  usr = User.getUserWithNick(fromnick)                                     #find own record
  return ret_fail('own user not found') if usr == nil  #must be error

  clist = JSON.parse(usr.clist)
  index = clist['nicks'].index(tonick)
  return ret_fail('not in list') if index == nil     #that nick is not in contact list!

  tousr = User.getUserWithNick(tonick)
  return ret_fail('addressee not found') if usr == nil  #must be error

  if message['type'] != 'auth_request'     #Normal message
    state = clist['authstate'][index]
    return ret_fail('not authorized') if state != 't'   #failure: not authorized!
  else                                     #its an authorization request!
    return ret_fail('already given') if clist['authstate'][index] == 't'  #already has permission!
    return ret_fail('already sent') if clist['authstate'][index] == 'p'  #already sent a request!

    #ok... its a valid auth request... so set state to 'p' and update db record
    clist['authstate'][index] = 'p' #awaiting to be answered
    usr.clist = JSON.generate(clist)
    usr.save
  end

  #append message to addressees message queue, update database record
  addresseequeue = JSON.parse(tousr.msgqueue)
  addresseequeue['messages'].push(message)
  tousr.msgqueue = JSON.generate(addresseequeue)
  tousr.save

  return ret_success
end

#client asks for all queued messages from other users (IMs and auth requests and stuff)
#returns empty list if empty... so always succeeds
def pull_queue(ownnick)
  usr = User.getUserWithNick(ownnick)                                      #find own record
  return ret_fail(ownnick+' not found in db') if usr == nil  #must be error

  queue = JSON.parse(usr.msgqueue)                                         #get queue

  #to prevent unneccessary rewriting of the record...
  if queue['messages'].length != 0
    #not empty -> remove data from the database
    usr.msgqueue = "{\"messages\":[]}"                                       #empty queue
    usr.save                                                                 #update database record
  end

  return {'response'=>true, 'messages'=> queue['messages']}                #return message queue
end

#client asks another user for authorization
def request_auth(from, to, message)
  #handeled by send_im
  return send_im(from, to, message)
end

#client gives permission to contact
def grant_auth(from, to)
  ownusr = User.getUserWithNick(from)
  ownclst = JSON.parse(ownusr.clist)
  index = ownclist['nicks'].index(to)
  return ret_fail(to+' not in your contact list') if index==nil #first add the user before accepting auth_request!

  tousr = User.getUserWithNick(to)
  return ret_fail('user not found!') if tousr == nil    #the user is not in the database

  #check the authorization state
  toclist = JSON.parse(tousr.clist)
  index = toclist['nicks'].index(from)
  return ret_fail('not in list of '+to) if index==nil
  return ret_fail(to+' is already authorized') if toclist['authstate'][index]=='t'
  return ret_fail('authorization was not requested') if toclist['authstate'][index]=='f' #makes no sense to grant before getting a request...

  #so state is pending -> lets change to given
  toclist['authstate'][index] = 't'
  tousr.clist = JSON.generate(toclist)
  #append notification to queue and save db record
  toqueue = JSON.parse(tousr.msgqueue)
  toqueue['messages'].push({'type'=>'auth_grant','from'=>from})
  tousr.msgqueue = JSON.generate(toqueue)
  tousr.save

  return ret_success
end

#client withdraws permission to contact / denies a request...
def withdraw_auth(from, to)
  tousr = User.getUserWithNick(to)
  return ret_fail('user not found!') if tousr == nil    #the user is not in the database

  #check the authorization state
  toclist = JSON.parse(tousr.clist)
  index = toclist['nicks'].index(from)
  return ret_fail('not in list of '+to) if index==nil
  return ret_fail(to+' is not authorized') if toclist['authstate'][index]=='f'  #nothing to withdraw

  #set state to f (no permission to write to "from")
  oldstate = toclist['authstate'][index]  #save old state
  toclist['authstate'][index] = 'f'
  #append notification...
  toqueue = JSON.parse(tousr.msgqueue)
  oldstate == 'p' ? type = 'auth_deny' : type = 'auth_withdraw' #if pending -> deny, if given -> withdraw
  toqueue['messages'].push({'type'=>type, 'from'=>from})
  tousr.msgqueue = JSON.generate(toqueue)
  tousr.save

  return ret_success
end
