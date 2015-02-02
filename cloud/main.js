/**
 * Login With VK.com
 *
 * An example web application implementing OAuth2 in Cloud Code
 *
 * There will be four routes:
 * / - The main route will show a page with a Login with VK link
 *       JavaScript will detect if it's logged in and navigate to /main
 * /authorize - This url will start the OAuth process and redirect to VK
 * /oauthCallback - Sent back from VK, this will validate the authorization
 *                    and create/update a Parse User before using 'become' to
 *                    set the user on the client side and redirecting to /main
 * /main - The application queries and displays some of the users VK data
 *
 */

/**
 * Load needed modules.
 */
var express = require('express');
var querystring = require('querystring');
var _ = require('underscore');
var Buffer = require('buffer').Buffer;

/**
 * Create an express application instance
 */
var app = express();

/**
 * VK specific details, including application id and secret
 */
var vkAppId = 'vk-app-id';
var vkAppSecret = 'vk-app-secret';
var vkScope = '';
var vkRedirectURI = 'https://<parse-app-name>.parseapp.com/oauthCallback'

var vkRedirectEndpoint = 'https://oauth.vk.com/authorize?';
var vkValidateEndpoint = 'https://oauth.vk.com/access_token';
var vkUserEndpoint = 'https://api.vk.com/method/users.get';

/**
 * In the Data Browser, set the Class Permissions for these 2 classes to
 *   disallow public access for Get/Find/Create/Update/Delete operations.
 * Only the master key should be able to query or write to these classes.
 */
var TokenRequest = Parse.Object.extend("TokenRequest");
var TokenStorage = Parse.Object.extend("TokenStorage");

/**
 * Create a Parse ACL which prohibits public access.  This will be used
 *   in several places throughout the application, to explicitly protect
 *   Parse User, TokenRequest, and TokenStorage objects.
 */
var restrictedAcl = new Parse.ACL();
restrictedAcl.setPublicReadAccess(false);
restrictedAcl.setPublicWriteAccess(false);

/**
 * Global app configuration section
 */
app.set('views', 'cloud/views');  // Specify the folder to find templates
app.set('view engine', 'ejs');    // Set the template engine
app.use(express.bodyParser());    // Middleware for reading request body

/**
 * Main route.
 *
 * When called, render the login.ejs view
 */
app.get('/', function(req, res) {
  res.render('login', {});
});

/**
 * Login with VK route.
 *
 * When called, generate a request token and redirect the browser to VK.
 */
app.get('/authorize', function(req, res) {
  var tokenRequest = new TokenRequest();
  // Secure the object against public access.
  tokenRequest.setACL(restrictedAcl);
  /**
   * Save this request in a Parse Object for validation when VK responds
   * Use the master key because this class is protected
   */
  tokenRequest.save(null, { useMasterKey: true }).then(function(obj) {
    /**
     * Redirect the browser to VK for authorization.
     * This uses the objectId of the new TokenRequest as the 'state'
     *   variable in the VK redirect.
     */
    res.redirect(
      vkRedirectEndpoint + querystring.stringify({
        client_id: vkAppId,
        scope: vkScope,
        redirect_uri: vkRedirectURI,
        v: '5.28',
        response_type: 'code',
        state: obj.id
      })
    );
  }, function(error) {
    // If there's an error storing the request, render the error page.
    res.render('error', { errorMessage: 'Failed to save auth request.'});
  });

});

/**
 * OAuth Callback route.
 *
 * This is intended to be accessed via redirect from VK.  The request
 *   will be validated against a previously stored TokenRequest and against
 *   another VK endpoint, and if valid, a User will be created and/or
 *   updated with details from VK.  A page will be rendered which will
 *   'become' the user on the client-side and redirect to the /main page.
 */
app.get('/oauthCallback', function(req, res) {
  var data = req.query;
  var token;
  /**
   * Validate that code and state have been passed in as query parameters.
   * Render an error page if this is invalid.
   */
  if (!(data && data.code && data.state)) {
    res.render('error', { errorMessage: 'Invalid auth response received.'});
    return;
  }
  var query = new Parse.Query(TokenRequest);
  /**
   * Check if the provided state object exists as a TokenRequest
   * Use the master key as operations on TokenRequest are protected
   */
  Parse.Cloud.useMasterKey();
  Parse.Promise.as().then(function() {
    return query.get(data.state);
  }).then(function(obj) {
    // Destroy the TokenRequest before continuing.
    return obj.destroy();
  }).then(function() {
    // Validate & Exchange the code parameter for an access token from VK
    return getVKAccessToken(data.code);
  }).then(function(access) {
    /**
     * Process the response from VK, return either the getVKUserDetails
     *   promise, or reject the promise.
     */
    var vkData = access.data;
    if (vkData && vkData.access_token && vkData.user_id) {
      token = vkData.access_token;
      return getVKUserDetails(token);
    } else {
      return Parse.Promise.error("Invalid access request.");
    }
  }).then(function(userDataResponse) {
    /**
     * Process the users VK details, return either the upsertVKUser
     *   promise, or reject the promise.
     */
    var userData = userDataResponse.data.response[0];
    if (userData && userData.first_name && userData.last_name && userData.uid) {
      return upsertVKUser(token, userData);
    } else {
      return Parse.Promise.error("Unable to parse VK data");
    }
  }).then(function(user) {
    /**
     * Render a page which sets the current user on the client-side and then
     *   redirects to /main
     */
    res.render('store_auth', { sessionToken: user.getSessionToken() });
  }, function(error) {
    /**
     * If the error is an object error (e.g. from a Parse function) convert it
     *   to a string for display to the user.
     */
    if (error && error.code && error.error) {
      error = error.code + ' ' + error.error;
    }
    res.render('error', { errorMessage: JSON.stringify(error) });
  });

});

/**
 * Logged in route.
 *
 * JavaScript will validate login and call a Cloud function to get the users
 *   VK details using the stored access token.
 */
app.get('/main', function(req, res) {
  res.render('main', {});
});

/**
 * Attach the express app to Cloud Code to process the inbound request.
 */
app.listen();

/**
 * Cloud function which will load a user's accessToken from TokenStorage and
 * request their details from VK for display on the client side.
 */
Parse.Cloud.define('getVKData', function(request, response) {
  if (!request.user) {
    return response.error('Must be logged in.');
  }
  var query = new Parse.Query(TokenStorage);
  query.equalTo('user', request.user);
  query.ascending('createdAt');
  Parse.Promise.as().then(function() {
    return query.first({ useMasterKey: true });
  }).then(function(tokenData) {
    if (!tokenData) {
      return Parse.Promise.error('No VK data found.');
    }
    return getVKUserDetails(tokenData.get('accessToken'));
  }).then(function(userDataResponse) {
    var userData = userDataResponse.data.response[0];
    response.success(userData);
  }, function(error) {
    response.error(error);
  });
});

/**
 * This function is called when VK redirects the user back after
 *   authorization.  It calls back to VK to validate and exchange the code
 *   for an access token.
 */
var getVKAccessToken = function(code) {
  var body = querystring.stringify({
    client_id: vkAppId,
    client_secret: vkAppSecret,
    code: code,
    redirect_uri:vkRedirectURI 
  });
  return Parse.Cloud.httpRequest({
    method: 'POST',
    url: vkValidateEndpoint,
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'Parse.com Cloud Code'
    },
    body: body
  });
}

/**
 * This function calls the vkUserEndpoint to get the user details for the
 * provided access token, returning the promise from the httpRequest.
 */
var getVKUserDetails = function(accessToken) {
  return Parse.Cloud.httpRequest({
    method: 'GET',
    url: vkUserEndpoint,
    params: { access_token: accessToken },
    headers: {
      'User-Agent': 'Parse.com Cloud Code'
    }
  });
}

/**
 * This function checks to see if this VK user has logged in before.
 * If the user is found, update the accessToken (if necessary) and return
 *   the users session token.  If not found, return the newVKUser promise.
 */
var upsertVKUser = function(accessToken, vkData) {
  var query = new Parse.Query(TokenStorage);
  query.equalTo('vkId', vkData.id);
  query.ascending('createdAt');
  // Check if this vkId has previously logged in, using the master key
  return query.first({ useMasterKey: true }).then(function(tokenData) {
    // If not, create a new user.
    if (!tokenData) {
      return newVKUser(accessToken, vkData);
    }
    // If found, fetch the user.
    var user = tokenData.get('user');
    return user.fetch({ useMasterKey: true }).then(function(user) {
      // Update the accessToken if it is different.
      if (accessToken !== tokenData.get('accessToken')) {
        tokenData.set('accessToken', accessToken);
      }
      /**
       * This save will not use an API request if the token was not changed.
       * e.g. when a new user is created and upsert is called again.
       */
      return tokenData.save(null, { useMasterKey: true });
    }).then(function(obj) {
      // Return the user object.
      return Parse.Promise.as(user);
    });
  });
}

/**
 * This function creates a Parse User with a random login and password, and
 *   associates it with an object in the TokenStorage class.
 * Once completed, this will return upsertVKUser.  This is done to protect
 *   against a race condition:  In the rare event where 2 new users are created
 *   at the same time, only the first one will actually get used.
 */
var newVKUser = function(accessToken, vkData) {
  var user = new Parse.User();
  // Generate a random username and password.
  var username = new Buffer(24);
  var password = new Buffer(24);
  _.times(24, function(i) {
    username.set(i, _.random(0, 255));
    password.set(i, _.random(0, 255));
  });
  user.set("username", username.toString('base64'));
  user.set("password", password.toString('base64'));
  // Sign up the new User
  return user.signUp().then(function(user) {
    // create a new TokenStorage object to store the user+VK association.
    var ts = new TokenStorage();
    ts.set('vkId', vkData.id);
    ts.set('vkFirstName', vkData.first_name);
    ts.set('vkLastName', vkData.last_name);
    ts.set('accessToken', accessToken);
    ts.set('user', user);
    ts.setACL(restrictedAcl);
    // Use the master key because TokenStorage objects should be protected.
    return ts.save(null, { useMasterKey: true });
  }).then(function(tokenStorage) {
    return upsertVKUser(accessToken, vkData);
  });
}