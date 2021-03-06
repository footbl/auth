var crypto, graph, redis, url, key, User,
secondsInOneHour, milisecondsInOneHour, uri, client;

redis = require('redis');
url = require('url');
crypto = require('crypto');
graph = require('fbgraph');

secondsInOneHour = 60 * 60;
milisecondsInOneHour = secondsInOneHour * 1000;

exports.connect = function (rds, tokenKey, usr) {
  key = tokenKey;
  User = usr;
  if (rds) {
    uri = url.parse(rds);
    client = redis.createClient(uri.port, uri.hostname);

    if (uri.auth) {
      client.auth(uri.auth.split(':')[1]);
    }
  } else {
    client = redis.createClient();
  }
};

exports.credentials = function (timestamp, transactionId) {
  'use strict';

  timestamp = timestamp || new Date().getTime();
  transactionId = transactionId || crypto.createHash('sha1').update(crypto.randomBytes(10)).digest('hex');

  return {
    timestamp     : timestamp,
    transactionId : transactionId,
    signature     : crypto.createHash('sha1').update(timestamp + transactionId + key).digest('hex')
  };
};

exports.signature = function () {
  'use strict';

  return function (request, response, next) {
    var timestamp, transactionId, signature, validSignature, now;
    now = new Date().getTime();
    signature = request.get('auth-signature');
    timestamp = request.get('auth-timestamp');
    transactionId = request.get('auth-transactionId');
    validSignature = exports.credentials(timestamp, transactionId).signature;

    if (now - timestamp > milisecondsInOneHour) {
      return next(new Error('invalid signature'));
    }
    if (signature !== validSignature) {
      return next(new Error('invalid signature'));
    }
    return next();
  };
};

exports.token = function (user) {
  'use strict';

  var token, timestamp, key;

  timestamp = new Date().getTime();
  token = crypto.createHash('sha1').update(timestamp + user._id + key).digest('hex');

  client.set(token, user._id);
  client.expire(token, secondsInOneHour);

  return token;
};

exports.populateSession = function () {
  return function (request, response, next) {
    var token;
    token = request.get('auth-token');

    return client.get(token, function (error, id) {
      if (error || !id) {
        return next(error);
      }
      return User.findById(id, function (error, user) {
        request.session = user;
        return next(error);
      });
    });
  };
};

exports.session = function (type) {
  'use strict';

  return function (request, response, next) {
    var token;
    token = request.get('auth-token');

    return client.get(token, function (error, id) {
      if (error) {
        return next(error)
      }
      if (!id) {
        return next(new Error('invalid session'));
      }
      return User.findById(id, function (error, user) {
        if (error) {
          return next(error)
        }
        if (!user) {
          return next(new Error('invalid session'));
        }
        if (type && type !== user.type) {
          return next(new Error('invalid session'));
        }
        request.session = user;
        return next();
      });
    });
  };
};

exports.checkMethod = function (field, neasted, fte) {
  'use strict';

  return function (request, response, next) {
    var cmp;
    cmp = request[field];
    cmp = neasted ? cmp[neasted] : cmp;
    if (cmp._id.toString() !== request.session._id.toString() && (!fte || !request[field][fte])) {
      return next(new Error('invalid method'));
    }
    return next();
  };
};

exports.facebook = function () {
  'use strict';

  return function (request, response, next) {
    var token;
    token = request.get('facebook-token');
    if (!token) {
      return next();
    }
    return graph.get('/me?access_token=' + token, function (error, data) {
      if (!error && data && data.id) {
        request.facebook = data.id;
      }
      next();
    });
  };
};
