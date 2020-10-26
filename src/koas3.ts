import * as cors from '@koa/cors';
import * as Router from '@koa/router';
import { unlink } from 'fs';
import * as $RefParser from 'json-schema-ref-parser';
import { Context } from 'koa';
import * as koaBody from 'koa-body';
import * as send from 'koa-send';
import OpenapiRequestCoercer from 'openapi-request-coercer';
import OpenAPIRequestValidator, { OpenAPIRequestValidatorArgs } from 'openapi-request-validator';
import OpenAPISchemaValidator, { OpenAPISchemaValidatorResult } from 'openapi-schema-validator';
import OpenAPISecurityHandler, { SecurityHandlers } from 'openapi-security-handler';
import { OpenAPI, OpenAPIV2, OpenAPIV3 } from 'openapi-types';
import { join } from 'path';
import * as SwaggerUI from 'swagger-ui-dist';
import * as winston from 'winston';

interface IOperationControllerMapping {
    [controller: string]: IOperationMapping;
}

interface IOperationMapping {
    [operationId: string]: IOperationEntry;
}

export interface IOperationEntry {
    path: string;
    method: Method;
    operation: OpenAPIV3.OperationObject;
    instance?: string;
}

export class ControllerInstance {
    constructor(protected entry?: IOperationEntry) {}

    onDestroy?(): void;
}

const enum Method {
    head = 'head',
    get = 'get',
    post = 'post',
    put = 'put',
    patch = 'patch',
    delete = 'delete',
    options = 'options',
}

const SUPPORTED_METHODS = [
    Method.head,
    Method.get,
    Method.post,
    Method.put,
    Method.patch,
    Method.delete,
];

export interface IKOAS3Options {
    controllersPath: string | ((controllerName: string) => Promise<object>);
    mergeWithRouter?: Router;
    validateSpecification?: boolean;
    openapiJsonPath?: string;
    openapiDocsPath?: string;
    securityHandlers?: SecurityHandlers;
    corsOptions?: cors.Options;
    koaBodyOptions?: koaBody.IKoaBodyOptions;
    logger?: {
        info: winston.LeveledLogMethod;
        error: winston.LeveledLogMethod;
    };
}

export class OASSchemaValidationError extends Error {
    public errors: OpenAPISchemaValidatorResult['errors'];

    constructor(message: string, errors: OASSchemaValidationError['errors']) {
        super(message);
        this.errors = errors;
    }
}

const SwaggerDocsHtml = ({ title, openapiUrl }: { title: string; openapiUrl: string }) => {
    return `
  <!-- HTML for static distribution bundle build -->
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>${title}</title>
    <link rel="stylesheet" type="text/css" href="./swagger-ui.css" >
    <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32" />
    <link rel="icon" type="image/png" href="./favicon-16x16.png" sizes="16x16" />
    <style>
      html
      {
        box-sizing: border-box;
        overflow: -moz-scrollbars-vertical;
        overflow-y: scroll;
      }

      *,
      *:before,
      *:after
      {
        box-sizing: inherit;
      }

      body
      {
        margin:0;
        background: #fafafa;
      }

      body .topbar {display:none;}
    </style>
  </head>

  <body>
    <div id="swagger-ui"></div>

    <script src="./swagger-ui-bundle.js"> </script>
    <script src="./swagger-ui-standalone-preset.js"> </script>
    <script>
    window.onload = function() {
      // Begin Swagger UI call region
      
      // End Swagger UI call region

      window.ui = SwaggerUIBundle({
        url: "${openapiUrl}",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        displayOperationId: true,
        showExtensions: true,
        showCommonExtensions: true,
        defaultModelRendering: 'model',
        defaultModelExpandDepth: 5
      })
    }
  </script>
  </body>
</html>`;
};

const oasPath2RouterPath = (path: string): string => {
    return path.replace(/{/g, ':').replace(/}/g, '');
};

const mapToRouter = (
    router: Router,
    path: string,
    method: Method,
    operation: OpenAPIV3.OperationObject,
    controllerAction: (ctx: Context) => Promise<any | void>,
    {
        openapi,
        securityHandlers,
        instance,
    }: {
        openapi?: OpenAPIV3.Document;
        securityHandlers?: SecurityHandlers;
        instance?: string;
    } = {},
) => {
    const pathToMap = oasPath2RouterPath(path);
    // zostavime pole middlewares
    const middlewares: Array<(ctx: Context, next?: () => void) => void> = [];
    // 1. validator vstupu + coercer + params parser, doplnac default hodnot a tak dalej
    const validator: OpenAPIRequestValidatorArgs = {
        parameters: operation.parameters || [],
        requestBody: operation.requestBody as OpenAPIV3.RequestBodyObject,
    };
    // if (validator.requestBody && method === 'put') {
    //   console.log(path, JSON.stringify(validator.requestBody, null, 2));
    // }
    const coercerParams: OpenAPI.Parameters = [...(operation.parameters || [])];
    // doplnime formData parametre - kvoli chybe v openapi-request-coercer, ktory zle implementuje OAS3
    if (
        operation.requestBody &&
        (operation.requestBody as OpenAPIV3.RequestBodyObject).content['multipart/form-data']
    ) {
        coercerParams.push(
            ...Object.entries(
                ((operation.requestBody as OpenAPIV3.RequestBodyObject).content[
                    'multipart/form-data'
                ].schema as OpenAPIV3.NonArraySchemaObject).properties,
            ).map(([paramName, paramSchema]) => {
                return {
                    name: paramName,
                    in: 'formData',
                    schema: paramSchema,
                };
            }),
        );
    }
    const coercer = new OpenapiRequestCoercer({
        parameters: coercerParams,
    });
    // FIXME: toten validator nekontroluje multipart/form-data required!!!
    // (lebo skontroluje schema, a podla nej to ma byt string a koa-body tam da
    // objekt, takze by trebalo mu dat kontrolu na ctx.request.files
    const requestValidator = new OpenAPIRequestValidator(validator);
    middlewares.push(async (ctx: Context, next) => {
        const request = {
            body: ctx.request.body,
            params: ctx.params,
            query: ctx.query,
            headers: ctx.headers,
        };
        // console.log(request.body);
        coercer.coerce(request);
        const validatorErrors = requestValidator.validateRequest(request);
        if (validatorErrors) {
            ctx.throw(validatorErrors.status, 'RequestValidationError', {
                errors: validatorErrors.errors,
                request,
                validator,
            });
        }
        return next();
    });

    // 2. extendneme ctx.state
    middlewares.push(async (ctx: Context, next) => {
        ctx.state = { ...ctx.state, openapi, path, pathToMap, operation, instance };
        // doplnime response schemu
        const responseDefinition = operation.responses[201] || operation.responses[200];
        if (responseDefinition) {
            if (
                (responseDefinition as OpenAPIV3.ResponseObject).content &&
                (responseDefinition as OpenAPIV3.ResponseObject).content['application/json']
            ) {
                ctx.state.responseSchema = (responseDefinition as OpenAPIV3.ResponseObject).content[
                    'application/json'
                ].schema;
            }
        }
        return next();
    });

    // 3. security middleware
    if (operation.security) {
        const securityHandler = new OpenAPISecurityHandler({
            loggingKey: 'KOAS3Security',
            // these are typically taken from the global api doc
            securityDefinitions: ((openapi.components || {}).securitySchemes ||
                {}) as OpenAPIV2.SecurityDefinitionsObject,
            // these handle the operation security reference
            securityHandlers,
            // These are typically defined on an operation's openapi document.
            operationSecurity: operation.security,
        });
        middlewares.push(async (ctx: Context, next) => {
            await securityHandler.handle(ctx);
            return next();
        });
    }

    // 4. finalna controller funkcia, ktora zavola controllerAction a ak vratil nejaky response, nastavi ho do ctx.body
    middlewares.push(async (ctx: Context, next) => {
        const result = await controllerAction(ctx);
        if (result !== undefined) {
            ctx.body = result;
        }
        return next();
    });

    switch (method) {
        case Method.get:
        case Method.post:
        case Method.put:
        case Method.patch:
        case Method.delete:
            router[method](operation.operationId, pathToMap, ...middlewares);
    }
};

export const KOAS3 = async (
    specification: OpenAPIV3.Document,
    {
        controllersPath,
        mergeWithRouter,
        validateSpecification = true,
        openapiJsonPath = '/openapi.json',
        openapiDocsPath = '/docs',
        securityHandlers = {},
        corsOptions = {
            maxAge: 86400,
        },
        koaBodyOptions = { multipart: true },
        logger = null,
    }: IKOAS3Options,
): Promise<Router> => {
    const router = mergeWithRouter || new Router();

    // validacia specifikacie
    if (validateSpecification) {
        const oasvalidate = new OpenAPISchemaValidator({
            version: specification.openapi,
        }).validate(specification);
        // zvalidujeme oas3 objekt
        if (oasvalidate.errors && oasvalidate.errors.length > 0) {
            throw new OASSchemaValidationError(
                'OpenAPI schema validation failed',
                oasvalidate.errors,
            );
        }
    }

    if (!specification || !specification.paths) {
        throw new Error('Specification is not valid');
    }

    // resolvneme referencie
    const openapi: OpenAPIV3.Document = await $RefParser.dereference(specification);

    // pridame cors
    router.use(cors(corsOptions));

    // pridame bodyparser
    router.use(koaBody(koaBodyOptions));
    // pridame cleanup na files ktore boli uploadnute
    router.use(async (ctx: Context, next) => {
        let error: Error = null;
        try {
            await next();
        } catch (e) {
            error = e;
        }
        // cleanup files
        if (ctx.request.files) {
            await Promise.all(
                Object.entries(ctx.request.files).map(([fieldname, { path }]) => {
                    return new Promise((resolve) => {
                        logger?.info('Cleaning uploaded file %s / %s', fieldname, path);
                        unlink(path, (err) => {
                            if (err) {
                                logger?.error('Cleaning uploaded file error', err);
                            }
                            resolve();
                        });
                    });
                }),
            );
        }
        if (error) {
            throw error;
        }
    });

    const { paths } = openapi;
    const operationMappings: IOperationControllerMapping = {};
    Object.keys(paths).forEach((path: string) => {
        // we have a path
        const pathDefinition = paths[path];
        // defined controller for path
        const pathControllerName = pathDefinition['x-controller-name'] || 'index_ctrl';
        SUPPORTED_METHODS.forEach((method: Method) => {
            if (!pathDefinition[method]) {
                return;
            }
            const operation = { ...pathDefinition[method] };
            // parametre operacie mergneme s parametrami path
            if (pathDefinition.parameters) {
                operation.parameters = [
                    ...pathDefinition.parameters.filter(
                        ({
                            name: pathParameterName,
                            in: pathParameterLocation,
                        }: OpenAPIV3.ParameterObject) => {
                            // ak je uz parameter definovany v path, nepridavame ho
                            return !(operation.parameters || []).find(
                                ({
                                    name: operationParameterName,
                                    in: operationParameterLocation,
                                }: OpenAPIV3.ParameterObject) => {
                                    return (
                                        operationParameterName === pathParameterName &&
                                        operationParameterLocation === pathParameterLocation
                                    );
                                },
                            );
                        },
                    ),
                    ...(operation.parameters || []),
                ];
            }
            const finalControllerName = operation['x-controller-name'] || pathControllerName;
            const instance = pathDefinition['x-controller-instance'];

            if (operationMappings[finalControllerName]) {
                operationMappings[finalControllerName][operation.operationId] = {
                    path,
                    method,
                    operation,
                    instance,
                };
            } else {
                operationMappings[finalControllerName] = {
                    [operation.operationId]: {
                        path,
                        method,
                        operation,
                        instance,
                    },
                };
            }
        });
        // tu pridame options pre path - kvoli CORS
        if (!pathDefinition[Method.options]) {
            router.options(oasPath2RouterPath(path), async (ctx, next) => {
                await next();
            });
        }
    });

    // mame namapovane controller / operationId, ideme naimportovat moduly z controllerov
    await Promise.all(
        Object.keys(operationMappings).map(async (controllerName: string) => {
            const controllerPath =
                typeof controllersPath === 'string'
                    ? join(controllersPath, controllerName)
                    : controllerName;

            try {
                const controller = await (typeof controllersPath === 'string'
                    ? import(`${controllerPath}`) // resolving webpack import not as expresion, but like string
                    : controllersPath(controllerName));

                // po uspesnom importe namapujeme router na kazdu operaciu
                Object.keys(operationMappings[controllerName]).forEach((operationId) => {
                    const operationDefinition = operationMappings[controllerName][operationId];
                    const instance = operationDefinition.instance;
                    let operationInController: (ctx: Context) => Promise<any | void>;

                    if (instance && instance in controller) {
                        operationInController = async (...restParams: any[]) => {
                            const newInstance = new (controller[
                                instance
                            ] as typeof ControllerInstance)(operationDefinition);

                            const result = await newInstance[operationId](...restParams);
                            if ('onDestroy' in newInstance) {
                                newInstance.onDestroy();
                            }
                            return result;
                        };
                    } else {
                        operationInController = controller[operationId];
                    }

                    if (operationInController) {
                        mapToRouter(
                            router,
                            operationDefinition.path,
                            operationDefinition.method,
                            operationDefinition.operation,
                            operationInController,
                            { openapi, securityHandlers, instance },
                        );
                    } else {
                        // nemame operaciu, namapujeme error
                        mapToRouter(
                            router,
                            operationDefinition.path,
                            operationDefinition.method,
                            operationDefinition.operation,
                            async (ctx) => {
                                ctx.throw(
                                    501,
                                    `Invalid controller(instance)/operation specified: ${controllerName}${
                                        instance && '(' + instance + ')'
                                    }/${operationId}`,
                                );
                            },
                            { openapi, securityHandlers, instance },
                        );
                    }
                });
            } catch (error) {
                // If the module belonging to a specific tag (controller) isn't found: create a stub if the flag is set.
                if (error.code === 'MODULE_NOT_FOUND') {
                    logger?.info(`Cannot find controller ${controllerPath}`);
                    // // pre kazdu operaciu spravime 501
                    Object.keys(operationMappings[controllerName]).forEach((operationId) => {
                        const operationDefinition = operationMappings[controllerName][operationId];
                        mapToRouter(
                            router,
                            operationDefinition.path,
                            operationDefinition.method,
                            operationDefinition.operation,
                            async (ctx) => {
                                ctx.throw(
                                    501,
                                    `Invalid controller/operation specified: ${controllerName}/${operationId}`,
                                );
                            },
                            { openapi, securityHandlers },
                        );
                    });
                } else {
                    throw error;
                }
            }
        }),
    );

    // nastavime openapi.json route
    router.get('_openapi', openapiJsonPath, (ctx) => {
        if (ctx.query.resolved) {
            ctx.body = openapi;
        } else {
            ctx.body = specification;
        }
    });

    // nastavime docs route
    const docsMw = async (ctx: Context) => {
        if (!ctx.params.path && !ctx.path.endsWith('/')) {
            return ctx.redirect(`${ctx.path}/`);
        }
        try {
            if (!ctx.params.path) {
                ctx.type = 'text/html';
                ctx.body = SwaggerDocsHtml({
                    title: `${openapi.info.title} ${openapi.info.version}`,
                    openapiUrl: router.url('_openapi', {}),
                });
            } else {
                await send(ctx, ctx.params.path, {
                    root: SwaggerUI.absolutePath(),
                });
            }
        } catch (err) {
            if (err.status !== 404) {
                throw err;
            }
        }
    };
    router.get('_docs', openapiDocsPath, docsMw).get(`${openapiDocsPath}/:path*`, docsMw);
    // redirect / -> /docs
    if (!router.stack.find((route) => route.path === '/')) {
        router.get('/', (ctx: Context) => {
            return ctx.redirect(router.url('_docs', {}));
        });
    }

    return router;
};

export default KOAS3;
