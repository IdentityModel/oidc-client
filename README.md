# Looking for a new maintainer

I've been working as the main and (for the most part) only individual on this project for 6+ years. Much has changed since then in the work of JavaScript and many updates are needed here. I no longer have the time to keep up and maintain this library and project (well, really haven't for some time now as many know).

As such, I plan to disable PRs and won't be responding to issues going forward. The repo will be archived by the end of the year.

If anyone wishes to step up and maintain this project, then that is very welcome! I suggest forking and then once there's a track record for such a commitment I would be happy to provide a link to your new repo letting people know that it is now maintained elsewhere.

Please contact me if you're interested in doing this: [@BrockLAllen](https://twitter.com/BrockLAllen)

So long and thanks for all the fish.

--------------------------------------------------


[![npm package](https://badge.fury.io/js/oidc-client.svg)](https://www.npmjs.com/package/oidc-client)
[![CircleCI](https://circleci.com/gh/IdentityModel/oidc-client-js/tree/dev.svg?style=svg)](https://circleci.com/gh/IdentityModel/oidc-client-js/tree/dev)

# oidc-client

Library to provide OpenID Connect (OIDC) and OAuth2 protocol support for client-side, browser-based JavaScript client applications. 
Also included is support for user session and access token management.

## Install

##### Node.js

Node.js v4.4 or later required.

##### NPM

`npm install oidc-client --save`

**NOTE**: if you're not already using [babel-polyfill](https://www.npmjs.com/package/babel-polyfill) make sure you run
`npm install --save babel-polyfill` as well. Then include it in your build.

##### CommonJS
If you don't use a package manager or a module loader, then you can get the library from the `dist` folder on github [here](dist).

## Including in the browser

If you intend to use this library directly in a browser and are not using UMD/AMD then there is a compiled version in the [~/dist](dist) folder. 
It is already bundled/minified and contains the necessary dependencies and polyfills (mainly for ES6 features such as Promises).

If you are using UMD/AMD and/or you already have included an ES6 polyfill (such as babel-polyfill.js) then you can include the UMD packaged version of the file from the [~/lib](lib) folder.

## Building the Source

```
git clone https://github.com/IdentityModel/oidc-client-js.git
cd oidc-client-js
npm install
npm run build
```

## Running the Sample

`npm start`

and then browse to [http://localhost:15000](http://localhost:15000).

## Running the Tests

`npm test`

## Docs

Some initial docs are [here](https://github.com/IdentityModel/oidc-client-js/wiki).

## Feedback, Feature requests, and Bugs

All are welcome on the [issue tracker](https://github.com/IdentityModel/oidc-client-js/issues).
