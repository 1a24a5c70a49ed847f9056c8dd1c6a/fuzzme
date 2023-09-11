const crypto = require('crypto');
const html = require('html-entities');
const http = require('http');
const querystring = require('querystring');
const url = require('url');

const data = require('./data.js');

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 1337;

const MAC_SECRET = crypto.randomBytes(32).toString('hex');
const TOKEN_VALID_TIME = 600000; // 10 minutes in milliseconds
const PASSWORD_HASHING_ROUNDS = 20000;

const host = process.argv[2] || DEFAULT_HOST;
const port = process.argv[3] || DEFAULT_PORT;

const DEBUG = false;
function debugLog(...args) {
  if (DEBUG) {
    console.log(...args);
  }
}

const PATHS_200_BASIC = new Set([
	'/',
	'/index',
	'/index.html',
	'/index.php'
]);

const PATHS_418 = new Set([
	'/status',
	'/status/',
	'/STATUS',
	'/STATUS/'
]);

/* regular users (for login on /login path) */
const USERS = {
	'rocket': computePasswordHash('soccer'),
	'phantom': computePasswordHash('q1w2e3r4t5'),
	'Thomas': computePasswordHash('monkey12'),
	'flash': computePasswordHash('bullshit'),
	'admin': computePasswordHash('JaHeWEDkcTkkPerxA9afxr9teD2WNR')
}

/* users on admin.fuzz subdomain */
const ADMIN_USERS = {
	'anVzdGluOnN0YXJ3YXJz' : 'justin',
	'd2VibWFzdGVyOmRhbGxhcw==' : 'webmaster'
}

function successResponse(path, res) {
	var respText = "<h1>Simple Fuzzing Demo</h1>";
	respText += "<p>You found the main page it seems.</p><br>";
	respText += `response for <tt>${html.encode(path)}</tt>`;
	res.end(respText);
}

function teapotResponse(path, res) {
	var respText = `<img src="data:image/svg+xml;base64,${data.IMG_TEAPOT_B64}" height="100%" width="100%"/>`;
  res.statusCode = 418;
	res.end(respText);
}

/* intentional RXSS */
function errorResponse(req, res) {
  getParams = querystring.parse(url.parse(req.url).query);
  if (! ('msg' in getParams)) {
    res.statusCode = 302;
    res.appendHeader('Location', '/error?msg=Generic+Error');
    return res.end('');
  }
  msg = getParams['msg']
  res.end(`<h1>Error</h1>${msg}`); 
}

function computePasswordHash(passwordString) {
	const hash = crypto.createHash('sha256');
	hash.update(passwordString);
	let hashVal = hash.copy().digest('hex');
	for (let i = 0; i < PASSWORD_HASHING_ROUNDS; ++i) {
		hashVal = hash.copy().digest('hex');
	}	
	return hashVal;	
}

function computeHmac(dataString) {
	const hmac = crypto.createHmac('sha256', MAC_SECRET);
	hmac.update(dataString);
	return hmac.digest('hex');
}

function generateSessionToken(name) {
	const data = {
		iat: Date.now(),
		name: name
	}
	const dataString = btoa(JSON.stringify(data));
	return computeHmac(dataString) + '.' + encodeURIComponent(dataString);
}

/* intentionally allows time-based user enum for large values of PASSWORD_HASHING_ROUNDS */
function autenticateUser(username, password) {
	function wait(ms){
		let start = new Date().getTime();
		let end = start;
		while(end < start + ms) {
			end = new Date().getTime();
		}
	}
	
	wait(2);
	if (!(username in USERS)) {
		return null;
	}
	const passwordHash = computePasswordHash(password);
	if (passwordHash !== USERS[username]) {
		return null;
	}
	return generateSessionToken(username);
}

function checkAndExtractToken(encoded) {
	if (!encoded) {
		return null;
	}
	const parts = encoded.split('.');
	if (parts.length != 2) {
		return null;
	}
	const macPart = parts[0];
	const digest = computeHmac(parts[1]);
	if (digest !== macPart) {
		return null;
	}
	const dataObject = JSON.parse(atob(parts[1]));
	if (typeof(dataObject?.iat) !== 'number' || (Date.now() - dataObject.iat) > TOKEN_VALID_TIME) {
		return null;
	}
	return dataObject;	
}

function parseCookies (cookieHeader) {
	const list = {};
	if (!cookieHeader) {
		return list;
	}

	cookieHeader.split(`;`).forEach(function(cookie) {
		let [ name, ...rest] = cookie.split(`=`);
		name = name?.trim();
		if (!name) {
			return;
		}
		const value = rest.join(`=`).trim();
		if (!value) {
			return;
		}
		list[name] = decodeURIComponent(value);
	});
	return list;
}

function checkAccess(req) {
	const cookies = parseCookies(req.headers.cookie);
	if (!cookies || ! 'session' in cookies) {
		return null;
	}
	const sessionCookie = cookies.session;
	return checkAndExtractToken(sessionCookie);
}

function loginResponse(req, res) {
	function buildLoginForm(msg) {
		let loginForm = 
			`<h1>Login</h1>
			<form action="/login" method="POST">
			<input type="text" name="uname" placeholder="username" class="field">
			<input type="password" name="pw" placeholder="password" class="field">
			<input type="submit" value="Login" class="btn">
			</form>`;
		if (msg) {
			loginForm += `<br>${msg}`;
		}
		return loginForm;
	}

	const authenticatedLocation = '/login/success';
	
	if (req.method === 'GET') {
		if (checkAccess(req)) {
			res.appendHeader('Location', authenticatedLocation);
			res.statusCode = 301;
			return;
		}
		const loginForm = buildLoginForm(null);
		res.end(loginForm);
		return;
	} else if (req.method === 'POST') {
		const errorResponse = 'Invalid credentials.';
		let body = ''
		req.on('data', function(data) {
			body += data;
		})
		req.on('end', function() { 
			const params = querystring.parse(body);
			if (!params || ! 'uname' in params || ! 'pw' in params) {
				res.end(buildLoginForm(errorResponse));
				return;
			}
			const authToken = autenticateUser(params.uname, params.pw);
			if (! authToken) {
				res.end(buildLoginForm(errorResponse));
				return;
			}
			const authCookie = `session=${authToken}; SameSite=Strict; HttpOnly`;
			res.appendHeader('Set-Cookie', authCookie);
			res.appendHeader('Location', authenticatedLocation);
			res.statusCode = 302;
			res.end('Not logged in!');
		})
	}
}

function loginSuccessResponse(req, res) {
	const authToken = checkAccess(req);
	if (!authToken) {
		return res.end('<h1>Not logged in!</h1>');
	}
	const loginDate = new Date(authToken.iat);
	const expiryDate = new Date(authToken.iat + TOKEN_VALID_TIME);
	const respText = 
		`<h1>Welcome ${html.encode(authToken.name)}</h1>
		Logged in at ${loginDate}<br>
		Expires at ${expiryDate}`
	res.end(respText);
}

function handleGenericHost(req, res) {
	const parsed = url.parse(req.url);
	const path = parsed.pathname;
	const searchParams = new URLSearchParams(parsed.query);
	const lastPart = path.substring(path.lastIndexOf('/') + 1);
	const num = Number(lastPart);

	if (!isNaN(num) && num > 0) {
		const redirectLocation = `/number?num=${num}`;
		res.appendHeader('Location', redirectLocation);
		res.statusCode = 301;
		res.end(`see ${redirectLocation}`);
		return;
	}
	if (path === '/number') {
		param = searchParams?.get('num');
		const n = Number(param);
		if (!isNaN(n)) {
			res.end(`${param} is a number.`);
		} else {
			res.end(`${param} is not a number.`);
		}
		return;
	}
	if (path === '/login') {
		return loginResponse(req, res);
	}
	if (path === '/login/success') {
		return loginSuccessResponse(req, res);
	}
  if (path.startsWith('/error')) {
    return errorResponse(req, res);
  }
	if (PATHS_200_BASIC.has(path)) {
		return successResponse(req.url, res);
	} 
	if (PATHS_418.has(path)) {
		return teapotResponse(req.url, res);
	}
	
	res.end('no match');
}


function handleAdminHost(req, res) {
	const authHeader = req.headers['authorization'];
	if (typeof(authHeader) === 'string' && authHeader.startsWith('Basic ')) {
		const auth = authHeader.substring(6);
		if (auth in ADMIN_USERS) {
			const username = ADMIN_USERS[auth];
			res.statusCode = 200;
			let respText = "<h1>Admin Panel</h1>";
			respText += `Welcome, ${html.encode(username)}!`; 
			res.end(respText);
			return;
		}
	}
	res.appendHeader('WWW-Authenticate', 'Basic realm=/');
	res.statusCode = 401;
	res.end();
}

const server = http.createServer((req, res) => {
	const host = req.headers['host'];	

	if (host === 'admin.fuzz' || host == `admin.fuzz:${port}`) {
		handleAdminHost(req, res);
	} else {
		handleGenericHost(req, res);
	}
});



server.listen(port, host, () => {
  console.log(`Server running at http://${host}:${port}/`);
});

