var _ = require('underscore');
var camelize = require('camelize');
var platform = require('platform');

var nonceUtil = require('./nonce');

var ALL_HEADERS = [
  'X-Content-Security-Policy',
  'Content-Security-Policy',
  'X-WebKit-CSP'
];

var DIRECTIVES = [
  'default-src',
  'script-src',
  'object-src',
  'img-src',
  'media-src',
  'frame-src',
  'font-src',
  'connect-src',
  'style-src',
  'report-uri',
  'sandbox'
];

var MUST_BE_QUOTED = [
  'none',
  'self',
  'unsafe-inline',
  'unsafe-eval',
  'nonce'
];

var HAS_NONCE = [
  'default-src',
  'script-src',
  'style-src'
];

module.exports = function csp(options) {
  console.log('options', options);

  options = _.clone(options) || { 'default-src': ["'self'"] };
  console.log('setAllHeaders1', options.setAllHeaders);
  var reportOnly = options.reportOnly || false;
  var setAllHeaders = options.setAllHeaders || false;
  console.log('setAllHeaders2', setAllHeaders);
  var safari5 = options.safari5 || false;
  var nonceFallback = options.nonceFallback || false;

  DIRECTIVES.forEach(function (directive) {
    var cameledKey = camelize(directive);
    var cameledValue = options[cameledKey];
    if (cameledValue && (cameledKey !== directive)) {
      if (options[directive]) {
        throw new Error(directive + ' and ' + cameledKey + ' specified. Specify just one.');
      }
      options[directive] = cameledValue;
      delete options[cameledKey];
    }

    var value = options[directive];
    var shouldWrapInArray = (_(value).isString()) && (
      (directive !== 'sandbox') ||
      ((directive === 'sandbox') && (value !== true))
    );
    if (shouldWrapInArray) {
      options[directive] = value.split(/\s/g);
    }
  });

  _.each(options, function (value, directive) {
    if (Array.isArray(value)) {
      MUST_BE_QUOTED.forEach(function (must) {
        if (value.indexOf(must) !== -1) {
          throw new Error(value + ' must be quoted');
        }
      });

      var nonceCount = value.filter(function(src) {
        return src === "'nonce'";
      }).length;
      if (nonceCount === 1) {
        if (HAS_NONCE.indexOf(directive) === -1) {
          throw new Error("'nonce' should not be in '" + directive + "' directive");
        }
      } else if (nonceCount === 2) {
        throw new Error("multiple 'nonce' specified. Specify just one for each directive");
      }
    } else {
      MUST_BE_QUOTED.forEach(function (must) {
        if (value === must) {
          throw new Error(value + ' must be quoted');
        }
      });

      if (value === "'nonce'") {
        if (HAS_NONCE.indexOf(directive) === -1) {
          throw new Error("'nonce' should not be in '" + directive + "' directive");
        }
      }
    }
  });

  if (reportOnly && !options['report-uri']) {
    throw new Error('Please remove reportOnly or add a report-uri.');
  }

  return function csp(req, res, next) {

    var headers = [];
    var policy = {};

    var browser = platform.parse(req.headers['user-agent']);
    var version = parseFloat(browser.version);
    console.log(req.headers['user-agent']);
    console.log(browser.name, version);

    DIRECTIVES.forEach(function (directive) {
      var value = options[directive];
      if ((value !== null) && (value !== undefined)) {
        // clone
        policy[directive] = Array.isArray(value) ? value.slice() : value;
      }
    });

    for (var i = 0; i < HAS_NONCE.length; i++) {
      var sourceList = policy[HAS_NONCE[i]];
      if (!sourceList) {
        continue;
      }
      var idx = sourceList.indexOf("'nonce'");
      if (idx !== -1) {
        if (!res.locals) {
          // for pure connect (witout express) environment
          res.locals = Object.create(null);
        }
        if (!res.locals.cspNonce) {
          try {
            res.locals.cspNonce = nonceUtil.generateNonceValue();
          } catch (failToGenerateRandomError) {
            return next(failToGenerateRandomError);
          }
        }
        sourceList[idx] = "'nonce-" + res.locals.cspNonce + "'";
        if (nonceFallback && sourceList.indexOf("'unsafe-inline'") === -1) {
          sourceList.push("'unsafe-inline'");
        }
      }
    }

    console.log('setAllHeaders3', setAllHeaders);
    switch (browser.name) {

      case 'IE':
        if (version >= 10) {
        headers.push('X-Content-Security-Policy');
        if (!setAllHeaders) {
          if (policy.sandbox) {
            policy = { sandbox: policy.sandbox };
          } else {
            policy = {};
          }
        }
      }
      break;

      case 'Firefox':

        if (version >= 23) {

        headers.push('Content-Security-Policy');

        if (version >= 31 && nonceFallback) {
          // Firefox 31+ supports nonce-value, but the fallback system is broken.
          // https://bugzilla.mozilla.org/show_bug.cgi?id=1004703
          _(policy).each(function(sourceList, directive) {
            var nonceCount = sourceList.filter(function(value) {
              return /^'nonce-.*'$/.test(value);
            }).length;
            if (nonceCount > 0) {
              policy[directive] = sourceList.filter(function(source) {
                return source !== "'unsafe-inline'";
              });
            }
          });
        }

      } else if ((version >= 4) && (version < 23)) {

        headers.push('X-Content-Security-Policy');

        policy['default-src'] = policy['default-src'] || ['*'];

        Object.keys(policy).forEach(function (key) {

          var value = policy[key];
          if (key === 'connect-src') {
            policy['xhr-src'] = value;
          } else if (key === 'default-src') {
            if (version < 5) {
              policy.allow = value;
            } else {
              policy['default-src'] = value;
            }
          } else if (key !== 'sandbox') {
            policy[key] = value;
          }

          if (Array.isArray(policy[key])) {

            var index;
            if ((index = policy[key].indexOf("'unsafe-inline'")) !== -1) {
              if (key === 'script-src') {
                policy[key][index] = "'inline-script'";
              } else {
                policy[key].splice(index, 1);
              }
            }
            if ((index = policy[key].indexOf("'unsafe-eval'")) !== -1) {
              if (key === 'script-src') {
                policy[key][index] = "'eval-script'";
              } else {
                policy[key].splice(index, 1);
              }
            }

          }

        });

      }

      break;

      case 'Chrome':
        if ((version >= 14) && (version < 25)) {
        headers.push('X-WebKit-CSP');
      } else if (version >= 25) {
        headers.push('Content-Security-Policy');
      }
      break;

      case 'Safari':
        if (version >= 7) {
        headers.push('Content-Security-Policy');
      } else if ((version >= 6) || ((version >= 5.1) && safari5)) {
        headers.push('X-WebKit-CSP');
      }
      break;

      case 'Opera':
        if (version >= 15) {
        headers.push('Content-Security-Policy');
      }
      break;

      case 'Chrome Mobile':
        if (version >= 14) {
        headers.push('Content-Security-Policy');
      }
      break;

      default:
        setAllHeaders = true;

    }
    console.log('setAllHeaders4', setAllHeaders);

    var policyString = _.map(policy, function (value, key) {
      if ((key === 'sandbox') && (value === true)) {
        return 'sandbox';
      } else if (Array.isArray(value)) {
        return key + ' ' + value.join(' ');
      } else {
        return key + ' ' + value;
      }
    }).join(';');

    if (setAllHeaders) {
      headers = ALL_HEADERS;
    }

    console.log(headers);
    if (policyString) {
      headers.forEach(function (header) {
        var headerName = header;
        if (reportOnly) {
          headerName += '-Report-Only';
        }
        res.setHeader(headerName, policyString);
      });
    }

    next();

  };

};
