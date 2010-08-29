/* Functions for the Login/Registration form
 * -> checking data, registering new users, logging in and setting everything for SecureMessage to work
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
					$("#captchapic").attr("src","data:image/png;base64,"+data.blob);
					$("#chash").attr("value", data.hash);	
				});
		return true;
	},

	/* invalid nick, free or registered nick? TODO: invalid */
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
		$.post("/check_nickname",{name: $("#nickname").attr("value")}, Login.checkNicknameCallback);
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

	/* password safe enough? TODO! */
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

	checkCaptcha: function() {
		if ($("#chash").attr("value") == SHA256($("#captcha").attr("value"))) {
			$("#captchacontrol").css("color","green");
			$("#captchacontrol").html("ok");
			return true;
		}

		/* failed captcha */
		$("#captchacontrol").css("color","red");
		$("#captchacontrol").html("not matching!");
		return false;
	},

	/* button to login or register */
	loginButtonClicked: function() {
		if ($("#nickcheck").text()=="registered") {
			SecureMessage.usrpwd = $("#password").attr("value");	// store user password in js to use for privkey decryption
	
			nick =	$("#nickname").attr("value");			//nickname
			pass =	SHA256($("#password").attr("value"));	//hashed password
	
			$.post("/login",
					{
						nickname:	nick,
					  	password:	pass
					}, Login.loginCallback);
	
		} else if ($("#nickcheck").text()=="free") {
			if( Login.checkPwd() && Login.comparePwds() && Login.checkCaptcha() ) {
	
				SecureMessage.usrpwd = $("#password").attr("value");	// store user password in js to use for privkey decryption
				SecureMessage.privkey = RSA.gen_keys(); //Generate and save new key
	
				nick =	$("#nickname").attr("value");			//nickname
				pass =	SHA256($("#password").attr("value"));	//hashed password
				pubkey = JSON.stringify(RSA.get_public_key(SecureMessage.privkey));	//public key
				cprivkey = GibberishAES.enc(JSON.stringify(SecureMessage.privkey), SecureMessage.usrpwd); //AES crypted private key for storage only...
	
				$.post("/register",
						{
							nickname:	nick,
					  		password:	pass,
							pubkey:		pubkey,
							cprivkey:	cprivkey
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
	
			$.cookie("nickname",$("#nickname").attr("value"));
	
			$.cookie("sessionid",data.sid);
	
			//if its login and not register -> cprivkey is sent too
			if (typeof data.cprivkey != 'undefined') {
				SecureMessage.privkey = JSON.parse(GibberishAES.dec(data.cprivkey, SecureMessage.usrpwd));
				SecureMessage.usrpwd = null; //delete saved cleartext user password
			}
			$.cookie("privkey",JSON.stringify(SecureMessage.privkey));
			
			SecureMessage.scpwd = RSA.decrypt(data.enc_scpwd, SecureMessage.privkey);	// session crypt password not as cookie cause must stay in client only
			$.cookie("scpwd",SecureMessage.scpwd);
	
			$("#loginstate").html("Hello, "+$.cookie("nickname")+"! <a href=\"javascript:Login.logout();\">Logout</a>");
		}
	},

	/* load the login/registration form */
	showLogin: function() {
		$.post("/show_login_form", function(text) {
					$("#loginstate").html(text);
					Login.initLoginFormHandlers();
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
		$.cookie("nickname",null);
		$.cookie("sessionid",null);
		$.cookie("scpwd",null);
		$.cookie("privkey",null);
		$.get("/logout?nickname="+$.cookie("nickname")+"&sessionid="+$.cookie("sessionid"));
		location.reload();
	},

	/* Set event handlers for the login form */
	initLoginFormHandlers: function() {
		$("#new_captcha").click(Login.getNewCaptcha);
		$("#login").click(Login.loginButtonClicked);
		$("#cancel").click(Login.hideLogin);
		$("#nickname").keyup(Login.checkNickname);
		$("#password").keyup(Login.checkPwd);
		$("#password_repeat").keyup(Login.comparePwds);
		$("#captcha").keyup(Login.checkCaptcha);
	}
}

if ($.cookie("nickname") != null) { // session running
	$("#loginstate").html("Hello, "+$.cookie("nickname")+"! <a href=\"javascript:Login.logout();\">Logout</a>");
}
