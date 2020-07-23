# OpanAPI v3 implementation for koa

## Usage example

```typescript
import * as fs from 'fs';
import * as jsyaml from 'js-yaml';
import * as Koa from 'koa';
import KOAS3, { IKOAS3Options } from 'koas3';

const createApp = async (
  openapiPath: string,
  options: IKOAS3Options
) => {
  // create openapi object
  const openapiFile = fs.readFileSync('/path-to-openapi.yaml', 'utf8');
  const openapi = jsyaml.safeLoad(openapiFile);

  // create Koa app
  const app = new Koa();

  // optionally setup app as proxy
  app.proxy = true;

  // optionaly use default error handler
  app.use(async (ctx, next) => {
    try {
      await next();
      if ([404, 405].includes(ctx.status)) {
        ctx.throw(ctx.status, `Path ${ctx.path} not found`);
      }
    } catch (err) {
      // example of error handling
      if (err instanceof RESTError) {
        ctx.status = err.statusCode;
        ctx.body = {
          statusCode: err.statusCode,
          name: err.name,
          description: err.description,
          payload: err.payload,
          userinfo: err.userinfo,
        };
      } else if (err.message === 'RequestValidationError') {
        const { status, name, message, ...payload } = err;
        ctx.status = typeof err.status === 'number' ? err.status : 500;
        ctx.body = {
          statusCode: ctx.status,
          name: 'INVALID_SCHEMA',
          description: err.message,
          payload,
        };
      } else {
        // application
        ctx.app.emit('error', err, ctx);
        ctx.status = typeof err.status === 'number' ? err.status : 500;
        ctx.body = {
          statusCode: ctx.status,
          name: err.name,
          description: err.message,
          payload: { error: err.message, stack: err.stack, originalError: err },
        };
      }
    }
  });

  // koas3 openapi magic
  const router = await KOAS3(openapi, options);

  // this is important - setup router prefix based on openapi servers
  // depends on your app logic, this just takes the first
  if (openapi.servers && openapi.servers.length) {
    const [serverDefinition] = openapi.servers;
    const url = URL.parse(serverDefinition.url);
    let routePrefix = url.pathname.replace(/\/$/, '') + '/';
    if (serverDefinition.variables) {
      Object.keys(serverDefinition.variables).forEach(k => {
        routePrefix = routePrefix.replace(
          new RegExp(`{${k}}`, 'g'),
          serverDefinition.variables[k].default,
        );
      });
    }

    router.prefix(routePrefix);
  }

  // resup KOAS3 router to the app
  app.use(router.routes());
  app.use(router.allowedMethods());

  app.on('error', err => {
    // this is any other error handler
    console.error('AppError:', err);
  });

  return app;
})();

// run the server
createApp(
  './path/to/openapi.yaml'),
  {
    controllersPath: './controllers',
    securityHandlers,
  }
).then(async (app) => {
  // make optional database connections

  //mongo.connector(Object.assign({ connect: false }, config.get('mongodb')));
  //await mongo.setup(dbSetup);
  //redis.create(config.get('redis'));

  http
    .createServer(app.callback())
    .listen({ port: 9000 }, () => {
      console.log('API is listening on port 9000');
    })
    .on('error', (ee: any) => {
      console.error(`Error starting server: ${ee}`);
    });
}).catch(async e => {
  console.error('ApiError:', e);
  // stop database connections

  //redis.disconnect();
  //await mongo.close();
})
```
