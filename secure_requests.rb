#!/usr/bin/env ruby
#Request Funcs for IM
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

#here all the fun happens :) this is an interface for the whole functionality...
#input and output are encrypted with the communication password for the session
#the data contains all commands and data as JSON... responses are encrypted JSON objects too

#hash => JSON => AES with session communication password => THAT will be returned
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
  if cmd == 'check_online_state'
    return check_online_state(ownnick,data['nickname'])
  end
  if cmd == 'delete_account'  #can also happen :(
    return delete_account(ownnick, params[:password]) #huge cleanup function
  end

  #for demonstration - secure calculator...
  if cmd == 'calc'
    return calc(data['expression'])
  end

  #########################
  #nothing matched
  return {'response'=>false,'report'=>'Unknown command: '+cmd}
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

#client requests own contact list -> return list with nicks, permissions and online states
def pull_clist(nick)
  usr = User.getUserWithNick(nick)
  return ret_fail('not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)
  clist = JSON.parse(usr.clist) #load JSON string of clist, make hash

  #check the online states of the users and add to the list to be returned
  clist['state'] = Array.new
  clist['nicks'].each{ |contactnick|
    clist['state'].push check_online_state(nick, contactnick, clist)['state']
  }

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

#check online state of a contact
#(second argument is provided when called with pull_clist to save a db request)
def check_online_state(source,nick,srcclist=nil)
  #normal call from client - get contact list to check authorization
  if srcclist == nil
    usr = User.getUserWithNick(source)
    return ret_fail(source+' not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)
    srcclist = JSON.parse(usr.clist) #load JSON string of clist, make hash
  end

  #if user not in contact list -> request denied
  index = clist['nicks'].index(nick)
  return ret_fail(nick+' not in your contact list') if index==nil

  #check now authorization - if no authorization, dont tell state (no permission) but thats not a ret_fail!
  return {'response'=>true,'state'=>'hidden'} if clist['authstate'][index] != 't'

  #everything's fine -> get state

  if $sessions.index(nick) != nil #that user has a session running -> online
    state = 'online'
  else
    state = 'offline'
  end

  return {'response'=>true, 'state'=>state}
end

#helper function  - used by login/logout
#send notification to contacts on login/logout
#nick - who logged in/out?, state - 'online'/'offline'
def broadcast_state(nick, state)
  #TODO: write function
  #get users clist, get the contacts clists and check their authorization to get the state
  #if its fine -> send the message to their queues

  return true
end

def delete_account(nick, password)
  #check whether logged in and correct password hash supplied
  usr = User.getUserWithNick(nick)
  return ret_fail('user does not exist!') if usr==nil #wtf?

  return ret_fail('password incorrect!') if password==usr.pwdhash #not matching

  #TODO: remove user from all his contacts and stuffz

  #ok... remove account :(
  User.delete(usr.id) #remove user from database

  #remove session (thread safe)
  $semaphore.synchronize do
    $sessions.delete(nick) #remove session associacion
  end

  return ret_success
end

#TODO: got_message message to notify the sender that a message was successfully delivered (identified by.. hash?)
