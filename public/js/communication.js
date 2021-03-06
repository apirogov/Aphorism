/* Encrypted communication layer for Aphorism
 * Copyright (C) 2010 Anton Pirogov
 * Licensed under GPLv3 or later
 */

/* This stuff works only after authentication
 * -> user logged in, got his encrypted private key and an encrypted session encryption password  (and the sessionid)
 * |-->	the sessionid and nickname are stored to be validated by the server for each request
 *  	(the server stores nick,sessionid,IP and the random session password as sessiondata)
 * -> decrypted it with login password (AES) -> IMCommand.privkey (Private Key of the user (RSA))
 * -> decrypted session password with private key (RSA) -> IMCommand.scpwd (Session Communication Password (AES))
 *  this information is useful if you want to use that concept in own projects
 *  I reccomend using my crypt.rb and crypt.js (and dependencies), cause their AES and RSA are compatible (openssl)
 */

/* create namespace if does not exist */
if (IMCommand == null || typeof(IMCommand) != "object") { var IMCommand = new Object();}

var IMCommand = {
	/* The core - wraps jquery post with encryption stuff...
	 * input: JSON object with request
	 * output: boolean false on fail or response object
	 */
	sync_send_json: function(object) {
		if (typeof IMCommand.sessionid == 'undefined')
				return false;	//no session running

		var json = JSON.stringify(object)

		IMCommand.sync_send_json.retval = true;
		$.ajax({url: '/imcommand', 		//synchronous ajax request, POST data: nick, sessionid and data
				data: {"nickname": IMCommand.nickname, "sessionid": IMCommand.sessionid, "data": json},
				success: function(data) {
					try {
						var obj = JSON.parse(data)
					} catch(e) {
						IMCommand.sync_send_json.retval = false;
						return false;
					}
					IMCommand.sync_send_json.retval = obj;
				}, 
				type: 'POST',
				async:	false
			});
		
		return IMCommand.sync_send_json.retval;
	}

};

/* create namespace if does not exist */
if (AphorismServer == null || typeof(AphorismServer) != "object") { var AphorismServer = new Object();}

/* this namespace has functions for all secure server calls */
AphorismServer = {
	/* TESTING FUNCTION FOR CLIENT<_>SERVER crypted COMMUNICATION */
	/* send a math expression.. recieve result... just for demostration and testing */
	calc: function(str) {
		return IMCommand.sync_send_json({"cmd": "calc", "expression": str}).response;
	},

	/* returns the contact list (nicks and authorization to write to them) */
	pull_clist: function() {
		return IMCommand.sync_send_json({"cmd": "pull_clist"});
	},

	/* tries to add a new contact */
	add_contact: function(nick) {
		return IMCommand.sync_send_json({"cmd": "add_contact", "nickname": nick});
	},

	/* tries to remove a contact */
	remove_contact: function(nick) {
		return IMCommand.sync_send_json({"cmd": "remove_contact", "nickname": nick});
	},
	
	/* pull IM queue with messages and auth requests etc */
	pull_queue: function() {
		return IMCommand.sync_send_json({"cmd": "pull_queue"});
	},

	/* send a new IM to a contact */
	/* input: nick of addressee, the output of IMCommand.pack_message */
	send_im: function(to,message) {
		return IMCommand.sync_send_json({
					"cmd": "send_im",
					"to": to,
					"message": {
						"type":"im_text",
						"data": message
					}
				});
	},

	/* send an authorization request to a contact
	 * input: nick of addressee, output of pack_message (to store "from" and optional text)  */
	request_auth: function(to, message) {
		return IMCommand.sync_send_json({
					"cmd": "request_auth",
					"to": to,
					"message": {
						"type":"auth_request",
						"data": message
					}
				});
	},

	/* input: nick... function accepts a request_auth */
	grant_auth: function(nick) {
		return IMCommand.sync_send_json({ "cmd": "grant_auth", "nickname": nick });
	 },

	/* input: nick... function denies a request_auth / withdraws an accepted request_auth */
	withdraw_auth: function(nick) {
		return IMCommand.sync_send_json({ "cmd": "withdraw_auth", "nickname": nick });
	 },

	/* get the online state for a specific user seperately (e.g. after adding) */
	check_online_state: function(nick) {
		return IMCommand.sync_send_json({ "cmd": "check_online_state", "nickname": nick });
	},
};


/* create namespace if does not exist */
if (AphorismClient == null || typeof(AphorismClient) != "object") { var AphorismClient = new Object();}

/* this namespace has the client "frontends" for the server functions */
AphorismClient = {
	
	process_queue: function() {
		if (typeof AphorismClient.stoppolling != 'undefined' && AphorismClient.stoppolling == true)
			return true;

		//pull queue from server
		AphorismClient.queue = AphorismServer.pull_queue().messages;

		//process all messages	(currently it means - just print them out)
		var currmsg = new Object();
		while (AphorismClient.queue.length > 0) {
			currmsg = AphorismClient.queue.shift(); 		//get first element
			$("#content").append("<div class=\"message\">"+JSON.stringify(currmsg)+"</div>");
		}

		//finished --> init next polling in 3 sec
		setTimeout("AphorismClient.process_queue()", 3000);

		return true;
	},

	// sets bool which triggers the end of the process_queue handling (called at AphorismClient shutdown)
	stop_polling: function() {
		AphorismClient.stoppolling = true;
	},

	initialize: function() {
		//request contact list
		var res = AphorismServer.pull_clist();
		if (res.response == false)
			return false; //failed to get the contact list
		AphorismClient.clist = res.clist; //loaded contact list

		/* init message polling every 3 sec */
		setTimeout("AphorismClient.process_queue()", 3000);

		return true;
	},

	shutdown: function() {
		AphorismClient.stop_polling();

		//send logout signal to server
		$.get("/logout?nickname="+IMCommand.nickname+"&sessionid="+IMCommand.sessionid);
	}

}

