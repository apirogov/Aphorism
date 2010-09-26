#!/usr/bin/env ruby
#Request Funcs for IM
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

#here all the fun happens :) this is an interface for the whole functionality...
#the data contains all commands and data as JSON... responses are JSON objects too

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

  #for demonstration - calculator...
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

#demonstration and testing of the interface - a calculator
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

  usr = User.first(:nickname=>person)
  return ret_fail('no such user') if usr == nil          #user does not exist !

  ownusr = User.first(:nickname => ownnick)  #get own record to get the contact list
  return ret_fail('already in list') if ownusr.contacts.first(:userid => usr.id) != nil

  c = ownusr.contacts.new
  c.userid = usr.id
  puts usr.id
  puts c.userid
  c.authgiven = 'f'
  c.save

  return ret_success
end

#client removes contact
def remove_contact(ownnick, person)
  usr = User.first(:nickname=>ownnick)
  return ret_fail('not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)

  otherusr = User.first(:nickname=>person)

  c = usr.contacts.first(:userid => otherusr.id)

  return ret_fail('not in clist') if c == nil  #user not in contact list

  #check whether the other user is given authorization
  if otherusr != nil      #user exists? if not, doesnt matter...
    hiscontact = otherusr.contacts.first(:userid => usr.id)
    if hiscontact != nil    #requesting user is in the clist of the user to be removed?
      return ret_fail('withdraw authorization first!') if hiscontact.authgiven == 't'
      hiscontact.authgiven = 'f'
      hiscontact.save
    end
  end

  #remove user from list
  c.destroy

  return ret_success
end

#client requests own contact list -> return list with nicks, permissions and online states
def pull_clist(nick)
  usr = User.first(:nickname=>nick)
  return ret_fail('not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)

  clist = Hash.new
  clist['nicks'] = []
  usr.contacts.each do |c|
    clist['nicks'].push User.first(:id => c.userid).nickname
  end

  #check the online states of the users and add to the list to be returned
  clist['state'] = Array.new
  clist['nicks'].each{ |contactnick|
    clist['state'].push check_online_state(nick, contactnick)['state']
  }

  return {'response'=>true, 'clist'=>clist}       #return data
end

#client sends an instant message (authorization request without authorization, other require authorization)
#this method handles auth_requests too... (called by auth_request(...) )
def send_im(fromnick,tonick,message)
  return ret_fail('can not send IM to yourself') if fromnick==tonick      #self-explainatory

  usr = User.first(:nickname=>fromnick)                                     #find own record
  return ret_fail('own user not found') if usr == nil  #must be error

  tousr = User.first(:nickname=>tonick)
  return ret_fail('addressee not found') if tousr == nil  #must be error

  contact = usr.contacts.first(:userid => tousr.id)
  return ret_fail('not in list') if contact == nil     #that nick is not in contact list!


  if message['type'] != 'auth_request'     #Normal message
    return ret_fail('not authorized') if contact.authgiven != 't'   #failure: not authorized!
  else                                     #its an authorization request!
    return ret_fail('already given') if contact.authgiven == 't'  #already has permission!
    return ret_fail('already sent') if contact.authgiven == 'p'  #already sent a request!

    #ok... its a valid auth request... so set state to 'p' and update db record
    contact.authgiven = 'p' #awaiting to be answered
    contact.save
  end

  #append message to addressees message queue, update database record
  msg = tousr.messages.new
  msg.data = JSON.generate({'from'=>fromnick, 'message'=>message})
  msg.save

  return ret_success
end

#client asks for all queued messages from other users (IMs and auth requests and stuff)
#returns empty list if empty... so always succeeds
def pull_queue(ownnick)
  usr = User.first(:nickname=>ownnick)                                      #find own record
  return ret_fail(ownnick+' not found in db') if usr == nil  #must be error

  messages = []
  usr.messages.each do |msg|
    messages << msg.data
    msg.destroy
  end

  return {'response'=>true, 'messages'=> messages}                #return message queue
end

#client asks another user for authorization
def request_auth(from, to, message)
  #handeled by send_im
  return send_im(from, to, message)
end

#client gives permission to contact
def grant_auth(from, to)
  ownusr = User.first(:nickname=>from)

  tousr = User.first(:nickname=>to)
  return ret_fail('user not found!') if tousr == nil    #the user is not in the database

  contact = ownusr.contacts.first(:userid => tousr.id)
  return ret_fail(to+' not in your contact list') if contact==nil #first add the user before accepting auth_request!


  #check the authorization state
  hiscontact = tousr.contacts.first(:userid => ownusr.id)
  return ret_fail('not in list of '+to) if hiscontact==nil
  return ret_fail(to+' is already authorized') if hiscontact.authgiven =='t'
  return ret_fail('authorization was not requested') if hiscontact.authgiven=='f' #makes no sense to grant before getting a request...

  #so state is pending -> lets change to given
  hiscontact.authgiven = 't'
  hiscontact.save

  #append notification to queue and save db record
  tousr.messages.create(:data => JSON.generate({'type'=>'auth_grant','from'=>from}))

  return ret_success
end

#client withdraws permission to contact / denies a request...
def withdraw_auth(from, to)
  tousr = User.first(:nickname=>to)
  return ret_fail('user not found!') if tousr == nil    #the user is not in the database

  #check the authorization state
  contact = tousr.contacts.first(:userid => User.first(:nickname=>from).id)
  return ret_fail('not in list of '+to) if contact == nil
  return ret_fail(to+' is not authorized') if contact.authgiven=='f'  #nothing to withdraw

  #set state to f (no permission to write to "from")
  oldstate = contact.authgiven  #save old state
  contact.authgiven = 'f'
  contact.save

  #append notification...
  oldstate == 'p' ? type = 'auth_deny' : type = 'auth_withdraw' #if pending -> deny, if given -> withdraw
  tousr.messages.create(:data => JSON.generate({'type'=>type, 'from'=>from}))

  return ret_success
end

#check online state of a contact
def check_online_state(source,nick,srcclist=nil)
  usr = User.first(:nickname=>source)
  return ret_fail(source+' not found') if usr == nil  #user not found (can only occur after own account deletion...as a bug)

  #if user not in contact list -> request denied
  contact = usr.contacts.first(:userid => User.first(:nickname => nick).id)
  return ret_fail(nick+' not in your contact list') if contact == nil

  #check now authorization - if no authorization, dont tell state (no permission) but thats not a ret_fail!
  return {'response'=>true,'state'=>'hidden'} if contact.authgiven != 't'

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
  usr = User.first(:nickname=>nick)
  return ret_fail('user does not exist!') if usr==nil #wtf?

  return ret_fail('password incorrect!') if password==usr.pwdhash #not matching

  #TODO: remove user from all his contacts and stuffz

  #ok... remove account :(
  usr.destroy #remove user from database

  #remove session
  $sessions.delete(nick) #remove session associacion

  return ret_success
end

#TODO: got_message message to notify the sender that a message was successfully delivered (identified by.. hash?)
