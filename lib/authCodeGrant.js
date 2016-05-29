/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var error = require('./error'),
	runner = require('./runner'),
	token = require('./token');

module.exports = AuthCodeGrant;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
	checkParams,
	checkClient,
	checkUserApproved,
	generateCode,
	saveAuthCode,
	redirect
];

/**
 * AuthCodeGrant
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function AuthCodeGrant(config, req, res, next, check, callback) {
	this.config = config;
	this.model = config.model;
	this.req = req;
	this.res = res;
	this.check = check;

	var self = this;
	runner(fns, this, function (err, result) {

		if(callback)
			return callback(req, res, next, err, result)

		if (err && res.oauthRedirect) {
			// Custom redirect error handler
			res.redirect(self.client.redirectUri + '?error=' + err.error +
				'&error_description=' + err.error_description + '&code=' + err.code);

			return self.config.continueAfterResponse ? next() : null;
		}

		next(err);
	});
}

/**
 * Check Request Params
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkParams (done) {
	var body = this.req.body;
	var query = this.req.query;
	if (!body && !query) return done(error('invalid_request'));

	// Response type
	this.responseType = body.response_type || query.response_type;
	if (this.responseType !== 'code') {
		return done(error('invalid_request',
			'Invalid response_type parameter (must be "code")'));
	}

	// Client
	this.clientId = body.client_id || query.client_id;
	if (!this.clientId) {
		return done(error('invalid_request',
			'Invalid or missing client_id parameter'));
	}

	// Redirect URI
	this.redirectUri = body.redirect_uri || query.redirect_uri;
	if (!this.redirectUri) {
		return done(error('invalid_request',
			'Invalid or missing redirect_uri parameter'));
	}

	 // Scope
	this.scopes = body.scope || query.scope;
	if (!this.scopes)
		return done(error('invalid_request', 'Invalid or missing scope parameter'));

	this.scopes = this.scopes.split(' ');
	console.log("this.scopes".redBG, this.scopes)
	

	done();
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkClient (done) {
	var self = this;
	self.model.getClient({req: self.req, clientId: self.clientId}, function (err, client) {
		if (err) return done(error('server_error', false, err));

		if (!client) {
			return done(error('invalid_client', 'Invalid client credentials'));
		} else if (Array.isArray(client.redirectUri)) {
			if (client.redirectUri.indexOf(self.redirectUri) === -1) {
				return done(error('invalid_request', 'redirect_uri does not match'));
			}
			client.redirectUri = self.redirectUri;
		} else if (client.redirectUri !== self.redirectUri) {
			return done(error('invalid_request', 'redirect_uri does not match'));
		}

		if (client.scopes) {
				var invalidScopes = []
				self.scopes.map(function(scope){
					if(client.scopes.indexOf(scope) === -1)
						invalidScopes.push(scope);
				});

				if (invalidScopes.length)
					return done(error('invalid_request', 'invalid scopes for this client '+invalidScopes.join(',')));
		};

		// The request contains valid params so any errors after this point
		// are redirected to the redirect_uri
		self.res.oauthRedirect = self.config.useRedirection;
		self.client = client;

		done();
	});
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkUserApproved (done) {
	var self = this;
	this.check(this.req, function (err, allowed, user) {
		if (err) return done(error('server_error', false, err));

		if (!allowed) {
			return done(error('access_denied',
				'The user denied access to your application'));
		}

		console.log("err, allowed, user".redBG, err, allowed, user)
		self.user = user;
		done();
	});
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateCode (done) {
	var self = this;
	token(this, 'authorization_code', function (err, code) {
		self.authCode = code;
		done(err);
	});
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveAuthCode (done) {
	var self = this;
	var expires = new Date();
	expires.setSeconds(expires.getSeconds() + this.config.authCodeLifetime);

	this.model.saveAuthCode({req: self.req, authCode: self.authCode, clientId: self.client.clientId, expires: expires.getTime(), user: self.user, scopes: self.scopes}, function (err) {
		if (err) return done(error('server_error', false, err));
		done();
	});
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function redirect (done) {
	var self = this;
	var state = this.req.query.state || this.req.body.state;
	if (self.res.oauthRedirect) {
		this.res.redirect(this.client.redirectUri + '?code=' + this.authCode +
			(state ? '&state=' + state : ''));
		return;
	}

	done(null, {
		authCode: self.authCode,
		state: state
	})

	return;


	if (this.config.continueAfterResponse)
		return done();
}
