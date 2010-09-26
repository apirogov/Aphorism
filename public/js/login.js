/* Functions for the Login/Registration form
 * -> checking data, registering new users, logging in and setting everything for IMCommand to work
 * Copyright (C) 2010 Anton Pirogov
 * Licensed under the GPLv3 or later
 */

if (Login == null || typeof(Login) != "object") { var Login = new Object();} /* create namespace if does not exist */

Login = {

	/* retrieve a new captcha pic for a new random number, and its sha256 hash */
	getNewCaptcha: function() {
		$("#captchacontrol").html("");
		$("#captcha").attr("value","");

		$.getJSON("/captcha", function(data) {
					/* get json data -> set pic into img and hash into field for control */
					$("#capid").attr("value", data.id);	
					$("#captchapic").attr("src","data:image/png;base64,"+data.blob);
				});
		return true;
	},

	/* invalid nick, free or registered nick? TODO: invalid nickname check */
	checkNickname: function() {
		if (typeof Login.checkNickname.running == 'undefined')
			Login.checkNickname.running = false;

		if (Login.checkNickname.running == true)
			return false;

		if( $("#nickname").attr("value").length < 5 ) {
			$("#nickcheck").css("color","red");
			$("#nickcheck").html("too short!");
			return false;
		}

		$("#nickcheck").css("color","black");
		$("#nickcheck").html("checking...");

		Login.checkNickname.running = true; /* Lock */
		$.get("/check_nickname",{name: $("#nickname").attr("value")}, Login.checkNicknameCallback);
		return true;
	},

	/* response about the nick from server */
	checkNicknameCallback: function(text) {
		if (text == 'free') {
			if ($("#nickcheck").text != "free") {
				$("#nickcheck").css("color","green");
				$("#nickcheck").html("free");
				Login.showHideRegister();
			}
		} else if (text == 'taken') {
			if ($("#nickcheck").text != "registered") {
				$("#nickcheck").css("color","blue");
				$("#nickcheck").html("registered");
				Login.showHideRegister();
			}
		} else
			alert("error");
		Login.checkNickname.running = false; /* unlock */
	},

	/* valid new user -> register form? */
	showHideRegister: function() {
		if ($("#nickcheck").html()=="free") {
			if (typeof Login.showHideRegister.shown_once == 'undefined') {
				Login.showHideRegister.shown_once = true;
				Login.getNewCaptcha();
		    }
			$("#register").slideDown("fast", function(){ $("#register").css("display","inline");}); 
		} else {
			$("#register").slideUp("fast"); 
		}
	},

	/* password safe enough? TODO! (in the end... would annoy while testing) */
	checkPwd: function() {
		$("#wrongpwd").html(""); /* empty it (user wants to retry) */
	
		if( $("#password").attr("value").length < 6 ) {
			$("#pwdcheck").css("color","red");
			$("#pwdcheck").html("too short!");
			return false;
		}
	
		/* no problems */
		$("#pwdcheck").css("color","green");
		$("#pwdcheck").html("ok");
		return true;
	},

	/* password & repeat password equal? */
	comparePwds: function() {
		if ( $("#password").attr("value") != $("#password_repeat").attr("value") ) {
			$("#pwdcontrol").css("color","red");
			$("#pwdcontrol").html("not matching!");
			return false;
		} 

		/* matches */
		$("#pwdcontrol").css("color","green");
		$("#pwdcontrol").html("ok");
		return true;
	},

	/* button to login or register */
	loginButtonClicked: function() {
		if ($("#nickcheck").text()=="registered") {
			nick =	$("#nickname").attr("value");			//nickname
			pass =	$("#password").attr("value");	//hashed password
	
			$.post("/login",
					{
						nickname:	nick,
					  	password:	pass
					}, Login.loginCallback);
	
		} else if ($("#nickcheck").text()=="free") {
			if( Login.checkPwd() && Login.comparePwds() ) {
				nick =	$("#nickname").attr("value");			//nickname
				pass =	$("#password").attr("value");	//hashed password
				cid = $("#capid").attr("value");	//Captcha id
				cval = $("#captcha").attr("value");	//Captcha text

				$.post("/register",
						{
							nickname:	nick,
					  		password:	pass,
							capid:		cid,
							capval:		cval				
						}, Login.loginCallback);
			}
		}
	},

	loginCallback: function(text) {
		if (text == "fail") {
			$("#password").attr("value","");
			$("#wrongpwd").css("color","red");
			$("#wrongpwd").html("password incorrect");
		} else if (text == "error") {
			alert("an error occured, try again later");
			location.reload();
		} else {	/* response = session id, session crypt pwd, (if login -> crypted private key) */
			data = JSON.parse(text);
	
			//store nickname and session id
			IMCommand.nickname = $("#nickname").attr("value");
			IMCommand.sessionid = data.sid;
	
			//update login link
			$("#loginstate").html("Hello, "+IMCommand.nickname+"! <a href=\"javascript:Login.logout();\">Logout</a>");

			AphorismClient.initialize();	//start up the client
			$(window).unload(function() {
					//terminate!
					Login.logout();
					return true;
					alert("Your session has been successfully terminated!");
					});

		}
	},

	/* load the login/registration form */
	showLogin: function() {
		$("#loginstate").load('/show_login_form', function(data) {
				Login.initLoginFormHandlers()
			}
			);
	},

	/* cancel -> set back Login hyperlink */
	hideLogin: function() {
		$("#loginstate").html("<a href=\"javascript:Login.showLogin();\">Login</a>");
		Login.showHideRegister.shown_once = undefined;
	},

	/* End session */
	logout: function() {
		AphorismClient.shutdown();	//Shutdown the client object properly
		location.reload();			//should empty the javascript variables -> session data
	},

	/* Set event handlers for the login form */
	initLoginFormHandlers: function() {
		$("#new_captcha").click(Login.getNewCaptcha);
		$("#login").click(Login.loginButtonClicked);
		$("#cancel").click(Login.hideLogin);
		$("#nickname").keyup(Login.checkNickname);
		$("#password").keyup(Login.checkPwd);
		$("#password_repeat").keyup(Login.comparePwds);
	}
}
