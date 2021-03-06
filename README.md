Content Security Policy middleware
==================================

[![Build Status](https://travis-ci.org/helmetjs/csp.svg?branch=master)](https://travis-ci.org/helmetjs/csp)

Content Security Policy helps prevent unwanted content being injected into your webpages; this can mitigate XSS vulnerabilities, unintended frames, malicious frames, and more. If you want to learn how CSP works, check out the fantastic [HTML5 Rocks guide](http://www.html5rocks.com/en/tutorials/security/content-security-policy/), the [Content Security Policy Reference](http://content-security-policy.com/), and the [Content Security Policy specification](http://www.w3.org/TR/CSP/).

Usage:

```javascript
var csp = require('helmet-csp');

app.use(csp({
  defaultSrc: ["'self'", 'default.com'],
  scriptSrc: ['scripts.com'],
  styleSrc: ['style.com'],
  imgSrc: ['img.com'],
  connectSrc: ['connect.com'],
  fontSrc: ['font.com'],
  objectSrc: ['object.com'],
  mediaSrc: ['media.com'],
  frameSrc: ['frame.com'],
  sandbox: ['allow-forms', 'allow-scripts'],
  reportUri: '/report-violation',
  reportOnly: false, // set to true if you only want to report errors
  setAllHeaders: false, // set to true if you want to set all headers
  safari5: false, // set to true if you want to force buggy CSP in Safari 5
  nonceFallback: false // set to true if you want to apply 'unsafe-inline' in browsers that doesn't support nonce-value
}));
```

You can specify keys in a camel-cased fashion (`imgSrc`) or dashed (`img-src`); they are equivalent.

There are a lot of inconsistencies in how browsers implement CSP. Helmet sniffs the user-agent of the browser and sets the appropriate header and value for that browser. If no user-agent is matched, it will set _all_ the headers with the 1.0 spec.

*Note*: If you're using the `reportUri` feature and you're using [csurf](https://github.com/expressjs/csurf), you might have errors. [Check this out](https://github.com/expressjs/csurf/issues/20) for a workaround.

### nonce-value

If you specify `'nonce'` in script-src, style-src and default-src,
random nonce-value (defined in [CSP 1.1](https://w3c.github.io/webappsec/specs/content-security-policy/)) is generated for each request.

```javascript
app.use(csp({
    scriptSrc: "'self' 'nonce'"
}));
// Content-Security-Policy: script-src 'self' 'nonce-yXKYLnUqXRLv546Ma/cnii0wktg='
app.get('/', function(req, res, next) {
  console.log(res.locals.cspNonce); // you can get a random nonce value (ex: "yXKYLnUqXRLv546Ma/cnii0wktg=")
  res.render('index'); // and you can use `cspNonce` variable in your templates
});
```
```html
<!-- in your templates -->
<script nonce="{{cspNonce}}">alert('foo')</script>
```

#### `nonceFallback`

If `nonceFallback` is true, `'unsafe-inline'` is added automatically.
Due to CSP 1.1 spec, if both nonce-value and `'unsafe-inline'` are present,
browsers supporting nonce-value use the former and the other browsers use the latter.

```javascript
app.use(csp({
    scriptSrc: "'self' 'nonce'",
    nonceFallback: true
}));
// Content-Security-Policy: script-src 'self' 'nonce-yXKYLnUqXRLv546Ma/cnii0wktg=' 'unsafe-inline'
```

However, [Firefox 31+ puts `'unsafe-inline'` ahead of nonce-value.](https://bugzilla.mozilla.org/show_bug.cgi?id=1004703 "1004703 – Tweak nonce- and hash-source interaction with unsafe-inline")
So `'unsafe-inline'` is not added in Firefox 31+.
