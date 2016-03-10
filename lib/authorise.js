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
 runner = require('./runner');

 module.exports = Authorise;

/**
* This is the function order used by the runner
*
* @type {Array}
*/
var fns = [
	getBearerToken,
	checkToken,
	checkScope
];

/**
* Authorise
*
* @param {Object}   config Instance of OAuth object
* @param {Object}   req
* @param {Object}   res
* @param {Function} next
*/
function Authorise (config, req, scopes, next) {
 	var self = this;
 	this.config = config;
 	this.model = config.model;
 	this.req = req;
 	if(scopes){
 		if(Array.isArray(scopes)){
 			this.requiredScope = scopes;
 		}else{
 			this.requiredScope = [scopes];
 		}
 	}

 	runner(fns, this, next);
}

function checkScope(done){
 	var self = this;
 	var requiredScope = self.requiredScope;
 	if (!requiredScope || !requiredScope.length)
 		return done();

 	var tokenScopes = self.req.scopes;
 	if (!tokenScopes || !tokenScopes.length)
 		return done(error('invalid_request', 'Invalid or missing scope'));

 	var missingScopes = [];

 	requiredScope.map(function(s){
 		if (tokenScopes.indexOf(s) === -1)
 			missingScopes.push(s);
 	})

 	if (!missingScopes.length)
 		return done();

 	return done(error('invalid_request', 'Required scope for this opertaion '+(missingScopes.length > 1? "are": "is")+' "'+missingScopes.join(',')+'"' ));

}

/**
* Get bearer token
*
* Extract token from request according to RFC6750
*
* @param  {Function} done
* @this   OAuth
*/
function getBearerToken (done) {
 	var headerToken = this.req.get('Authorization'),
 	getToken =  this.req.query.access_token,
 	postToken = this.req.body ? this.req.body.access_token : undefined;

	// Check exactly one method was used
	var methodsUsed = (headerToken !== undefined) + (getToken !== undefined) +
	(postToken !== undefined);

	if (methodsUsed > 1) {
		return done(error('invalid_request', 'Only one method may be used to authenticate at a time (Auth header,  ' +
			'GET or POST).'));
	} else if (methodsUsed === 0) {
		return done(error('invalid_request', 'The access token was not found'));
	}

	// Header: http://tools.ietf.org/html/rfc6750#section-2.1
	//console.log("headerToken".greenBG, headerToken)
	if (headerToken) {
		var matches = headerToken.match(/Bearer\s(\S+)/i);

		if (!matches) {
			return done(error('invalid_request', 'Malformed auth header'));
		}

		headerToken = matches[1];
	}

	// POST: http://tools.ietf.org/html/rfc6750#section-2.2
	if (postToken) {
	  	if (this.req.method === 'GET') {
	  		return done(error('invalid_request', 'Method cannot be GET When putting the token in the body.'));
	  	}

	  	if (!this.req.is('application/x-www-form-urlencoded')) {
	  		return done(error('invalid_request', 'When putting the token in the ' +
	  			'body, content type must be application/x-www-form-urlencoded.'));
	  	}
	}

	this.bearerToken = headerToken || postToken || getToken;
	done();
}

/**
* Check token
*
* Check it against model, ensure it's not expired
* @param  {Function} done
* @this   OAuth
*/
function checkToken (done) {
 	var self = this;
 	self.model.getAccessToken({req: self.req, accessToken: self.bearerToken}, function (err, token) {
 		if (err) return done(error('server_error', false, err));

 		if (!token) {
 			return done(error('invalid_token', 'The access token provided is invalid.'));
 		}

 		if (token.expires !== null && (!token.expires || token.expires < Date.now())) {
 			return done(error('invalid_token','The access token provided has expired.'));
 		}

		// Expose params
		self.req.oauth = { bearerToken: token };
		self.req.user = token.user ? token.user : { id: token.userId };
		//console.log("token".greenBG, token)
		self.req.scopes = token.scopes;

		done();
	});
}
