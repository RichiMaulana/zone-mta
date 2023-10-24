'use strict';

const config = require('wild-config');
const log = require('npmlog');
const restify = require('restify');
const ByteCounter = require('./byte-counter');
const Headers = require('mailsplit').Headers;
const MailDrop = require('./mail-drop');
const plugins = require('./plugins');
const MailComposer = require('nodemailer/lib/mail-composer');
const LeWindows = require('nodemailer/lib/mime-node/le-windows');
const util = require('util');
const internalCounters = require('./counters');
const addressTools = require('./address-tools');
const promClient = require('prom-client');
const ObjectId = require('mongodb').ObjectId;
const Joi = require('joi');
const cors = require('cors');
const multer = require('multer');

const lastBounces = [];
const storage = multer.memoryStorage();
const upload = multer(storage);

class CustomError extends Error {
    constructor(message, code, errors) {
        super(message || 'Internal Server Error');
        this.code = code || 500;
        this.errors = errors;
    }
}

class APIServer {
    constructor() {
        this.queue = false;
        this.closing = false;
        this.maildrop = new MailDrop();
        this.createServer();
    }

    setQueue(queue) {
        this.queue = this.maildrop.queue = queue;
    }

    successRes(res, data, code, message) {
        const resData = {
            status: 'Success',
            code,
            msg: message,
            data
        };
        res.json(code, resData);
    }

    failedRes(res, error) {
        const resData = {
            status: 'Failed',
            code: error.code,
            msg: error.message,
            error: error.errors || null
        };
        res.json(error.code, resData);
    }

    createServer() {
        this.server = restify.createServer();

        this.server.use(cors());
        this.server.use(restify.plugins.authorizationParser());
        this.server.use(restify.plugins.queryParser());
        this.server.use(restify.plugins.gzipResponse());
        this.server.use(restify.plugins.jsonBodyParser());

        this.server.pre((request, response, next) => {
            log.verbose('HTTP', request.url);
            next();
        });

        this.setupRoutes();
    }

    start(callback) {
        let returned = false;
        this.server.once('error', err => {
            if (returned) {
                return log.error('API', err);
            }
            returned = true;
            return callback(err);
        });

        this.server.listen(config.api.port, config.api.host, () => {
            if (returned) {
                return this.server.close();
            }
            returned = true;
            callback(null, true);
        });
    }

    close(callback) {
        this.closing = true;
        this.server.close(callback);
    }

    setupRoutes() {
        // Example handler for authentication. You should probably override it
        // with the config.plugins['core/http-auth'].url option
        this.server.get('/test-auth', (req, res, next) => {
            let time = new Date().toISOString();

            if (req.username !== config.api.user || req.authorization.basic.password !== config.api.pass) {
                res.statusCode = 401;
                res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
                return res.json({
                    time,
                    error: 'Authentication required'
                });
            }

            // the actual response does not matter as long as it's 2xx range
            res.json({
                user: req.username,
                time
            });

            next();
        });

        // Example handler for bounce notifications. You should probably override it
        // with the config.plugins['core/http-bounce'].url option and send the bounce notification to somewhere else
        this.server.post('/report-bounce', (req, res, next) => {
            res.send(202, req.params.id);
            lastBounces.push({
                id: req.params.id,
                to: req.params.to,
                returnPath: req.params.returnPath,
                seq: req.params.seq,
                category: req.params.category,
                time: req.params.time,
                response: req.params.response,
                fbl: req.params.fbl
            });
            if (lastBounces.length > 150) {
                lastBounces.splice(100);
            }
            return next();
        });

        // Information about last bounces reported to the example handler
        this.server.get('/bounces', (req, res, next) => {
            res.json(200, {
                bounces: lastBounces
            });
            return next();
        });

        // POST message = Nodemailer mail structure
        this.server.post('/send', (req, res, next) => {
            upload.array('attachments')(req, res, err => {
                if (err instanceof multer.MulterError) {
                    log.error('MULTER Upload', err.message, err);
                    return this.failedRes(res, new CustomError('Validation Error!', 400, { msg: `Cannot upload file to "${err.field}" field` }));
                } else if (err) {
                    log.error('MULTER Upload', err.message, err);
                    return this.failedRes(
                        res,
                        new CustomError('Internal server error', 500, { msg: 'Please contact customer support to escalate this problem!' })
                    );
                }

                let authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return this.failedRes(res, new CustomError('No token provided!', 401, { msg: 'Require token to access this route!' }));
                }
                authHeader = authHeader.split(' ')[1];

                const schema = Joi.object({
                    from: Joi.string().email().required(),
                    to: Joi.alternatives().try(Joi.string().email(), Joi.array().items(Joi.string().email())).required(),
                    cc: Joi.alternatives().try(Joi.string().email(), Joi.array().items(Joi.string().email())),
                    bcc: Joi.alternatives().try(Joi.string().email(), Joi.array().items(Joi.string().email())),
                    replyTo: Joi.string().email(),
                    subject: Joi.string().required(),
                    content: Joi.string().required(),
                    content_type: Joi.string().valid('html', 'text'),
                    attachments: Joi.array()
                });

                const { error: joiErr } = schema.validate(req.body);
                if (joiErr) {
                    return this.failedRes(res, new CustomError('Validation Error!', 400, { msg: joiErr.message }));
                }

                let data = req.body || {};
                let attachSize = 0
                if (req.files && !data.attachments) data.attachments = [];

                if (req.files) {
                    for (let row = 0; row < req.files.length; row++) {
                        let file = req.files[row];
                        let attachData = {
                            filename: file.originalname,
                            content: file.buffer.toString('base64'),
                            encoding: 'base64'
                        };
                        data.attachments.push(attachData);
                        attachSize = attachSize + file.size
                    }
                }

                const tokenCollection = this.queue.mongodb.collection('sendingtoken');
                const listdomainCollection = this.queue.mongodb.collection('listdomain');

                const options = { projection: { companyUuid: 1, token: 1, status: 1 } };

                tokenCollection.findOne({ token: authHeader }, options, (err, token) => {
                    if (err) {
                        log.error('API - Token', err);
                        return this.failedRes(
                            res,
                            new CustomError('Internal server error', 500, { msg: 'Please contact customer support to escalate this problem!' })
                        );
                    }
                    if (!token || authHeader !== token.token) {
                        return this.failedRes(res, new CustomError('Not authorized!', 401, { msg: 'Not authorized to access this route!' }));
                    }

                    if (token.status !== 'active') {
                        return this.failedRes(res, new CustomError('Token validation failed', 401, { msg: 'Your API sending token status is curently ' + token.status}))
                    }

                    const senderDomain = data.from.split('@')[1];
                    listdomainCollection.findOne({ domain: senderDomain }, { projection: { companyUuid: 1, domain: 1, maxSize: 1 } }, (err, domain) => {
                        if (err) {
                            log.error('API - List Domain', err);
                            return this.failedRes(
                                res,
                                new CustomError('Internal server error', 500, { msg: 'Please contact customer support to escalate this problem!' })
                            );
                        }
                        
                        let domainOwner;
                        if (domain) domainOwner = domain.companyUuid;
                        if (!domain || token.companyUuid !== domainOwner) {
                            return this.failedRes(res, new CustomError('Send access denied!', 401, { msg: 'You not owned the sending domain!' }));
                        }
                        
                        const attachLimit = domain?.maxSize ? domain?.maxSize : 14474894
                        if (attachSize > attachLimit) {
                            return this.failedRes(res, new CustomError('Sending failed', 400, {msg: 'Your attachment is over the limit', data: { max_attachment_size: attachLimit, current_attachment_size: attachSize }}))
                        }

                        if (!config.api.maildrop) {
                            return this.failedRes(res, new CustomError('Requested service not found', 404));
                        }

                        data.disableFileAccess = true;
                        data.disableUrlAccess = true;
                        if (data.content_type === 'html') {
                            data.html = data.content;
                        } else {
                            data.text = data.content;
                        }
                        delete data.content;
                        let mail = new MailComposer(data).compile();

                        let envelope = mail.getEnvelope();
                        envelope.id = this.queue.seqIndex.get();
                        envelope.interface = 'api';
                        envelope.origin = req.header('X-Originating-IP', false);
                        envelope.transtype = 'HTTP';
                        envelope.time = Date.now();
                        envelope.user = req.header('X-Authenticated-User', false);

                        let session = {
                            remoteAddress: req.connection.remoteAddress,
                            transmissionType: 'HTTP',
                            user: envelope.user
                        };

                        plugins.handler.runHooks('api:mail', [envelope, session], err => {
                            if (err) {
                                log.error('API - Send', err);
                                return this.failedRes(
                                    res,
                                    new CustomError('Internal server error', 500, { msg: 'Please contact customer support to escalate this problem!' })
                                );
                            }

                            let sourceStream = mail.createReadStream();
                            let transform = new LeWindows();

                            sourceStream.pipe(transform);
                            sourceStream.once('error', err => transform.emit('error', err));

                            this.maildrop.add(envelope, transform, (err, response) => {
                                if (err) {
                                    if (err.name === 'SMTPResponse') {
                                        return this.failedRes(res, new CustomError(err.message, 200));
                                    }
                                    log.error('API - Send', err);
                                    return this.failedRes(
                                        res,
                                        new CustomError('Internal server error', 500, { msg: 'Please contact customer support to escalate this problem!' })
                                    );
                                } else {
                                    const data = {
                                        id: envelope.id,
                                        from: envelope.from,
                                        to: envelope.to
                                    };
                                    this.successRes(res, data, 200, response);
                                }
                                next();
                            });
                        });
                    });
                });
            });
        });

        // POST message = Raw eml
        this.server.post('/send-raw', (req, res, next) => {
            if (!config.api.maildrop) {
                res.json(404, {
                    error: 'Requested service not found'
                });
                return next();
            }

            let payload = req.body ? req.body : req;
            let envelope = {
                id: this.queue.seqIndex.get(),
                interface: 'api',
                origin: req.header('X-Originating-IP', false),
                transtype: 'HTTP',
                time: Date.now(),
                user: req.header('X-Authenticated-User', false),
                envelopeFromHeader: true
            };

            let session = {
                remoteAddress: req.connection.remoteAddress,
                transmissionType: 'HTTP',
                user: envelope.user
            };

            plugins.handler.runHooks('api:mail', [envelope, session], err => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                    return next();
                }
                this.maildrop.add(envelope, payload, (err, response) => {
                    if (err) {
                        if (err.name === 'SMTPResponse') {
                            return res.json(200, {
                                message: err.message
                            });
                        }
                        res.json(500, {
                            error: err.message
                        });
                    } else {
                        res.json(200, {
                            id: envelope.id,
                            from: envelope.from,
                            to: envelope.to,
                            response
                        });
                    }
                    next();
                });
            });
        });

        this.server.put('/store/:id', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Queue not yet initialized'
                });
                return next();
            }

            let id = req.params.id;
            if (!id) {
                res.json(500, {
                    error: 'Missing Queue ID'
                });
                return next();
            }

            this.queue.store(id, req, err => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                } else {
                    res.json(200, {
                        success: true
                    });
                }
                next();
            });
        });

        this.server.get('/zones', (req, res, next) => {
            let zones = Object.keys(config.zones)
                .filter(zone => config.zones[zone] && !config.zones[zone].disabled)
                .map(zone => ({
                    name: zone
                }))
                .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
            res.json(200, zones);
            next();
        });

        // general information about some zone
        this.server.get('/counter/:type/:zone', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }

            let zone = req.params.zone
                ? req.params.zone
                : Object.keys(config.zones)
                      .filter(zone => config.zones[zone] && !config.zones[zone].disabled)
                      .sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));

            this.queue.count(zone, 'active', (err, active) => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                    return next();
                }
                this.queue.count(zone, 'deferred', (err, deferred) => {
                    if (err) {
                        res.json(500, {
                            error: err.message
                        });
                        return next();
                    }
                    res.json({
                        [req.params.type]: req.params.key || 'all',
                        active,
                        deferred
                    });
                    next();
                });
            });
        });

        // list queued recipients for a zone
        this.server.get('/queued/:type/:zone', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }

            let type = (req.params.type || '').toString().toLowerCase().trim();

            type = ['deferred', 'queued'].includes(type) ? type : 'queued';

            this.queue.listQueued(req.params.zone, type, 1000, (err, list) => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                    return next();
                }

                res.json({
                    zone: req.params.zone || 'all',
                    type,
                    list
                });

                next();
            });
        });

        // Streams message contents
        this.server.get('/fetch/:id', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }
            this.queue.getMeta(req.params.id, (err, meta) => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                    return next();
                }
                if (!meta) {
                    res.json(404, {
                        error: 'Selected message does not exist'
                    });
                    return next();
                }

                let byteCounter = new ByteCounter();
                let source = this.queue.retrieve(req.params.id);
                source.once('error', err => {
                    log.error('FETCH', '%s LOADFAIL error="%s"', err.message);
                    res.emit('error', err);
                });
                byteCounter.once('end', () => {
                    let stats = byteCounter.stats();
                    log.info(
                        'FETCH',
                        '%s LOADINFO %s',
                        req.params.id,
                        Object.keys(stats || {})
                            .map(key => key + '=' + stats[key])
                            .join(' ')
                    );
                });
                byteCounter.pipe(res);

                if ((req.query.body || '').toString().trim().toLowerCase() === 'yes') {
                    // stream only body
                    res.writeHead(200, {
                        'Content-Type': 'message/rfc822'
                    });
                    return source.pipe(byteCounter);
                }

                let headers = new Headers(meta.headers);
                res.writeHead(200, {
                    'Content-Type': 'message/rfc822'
                });

                byteCounter.write(headers.build());
                return source.pipe(byteCounter);
            });
        });

        // Returns message info in queue
        this.server.get('/message/:id', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }
            this.queue.getInfo(req.params.id, (err, info) => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                    return next();
                }
                if (!info) {
                    res.json(404, {
                        error: 'Selected message does not exist'
                    });
                    return next();
                }

                res.json(200, info);
                return next();
            });
        });

        // Deletes a message from the queue
        this.server.del('/message/:id/:seq', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }
            this.queue.remove(req.params.id, req.params.seq, err => {
                if (err) {
                    res.json(500, {
                        error: err.message
                    });
                    return next();
                }

                res.json(200, {
                    success: true
                });
                return next();
            });
        });

        // Sends a deferred message
        this.server.put('/message/:id/:seq', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }
            this.queue.update(
                req.params.id,
                req.params.seq,
                {
                    $set: {
                        queued: new Date()
                    }
                },
                err => {
                    if (err) {
                        res.json(500, {
                            error: err.message
                        });
                        return next();
                    }

                    res.json(200, {
                        success: true
                    });
                    return next();
                }
            );
        });

        // Returns blacklisted domains
        this.server.get('/blacklist', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }

            let list = this.queue.cache.sorted.filter(entry => /^blacklist:/.test(entry.key)).map(entry => entry.value);

            res.json({
                list
            });

            next();
        });

        // Returns message info in queue
        this.server.get('/internals', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }

            res.setHeader('content-type', 'text/plain; charset=utf-8');

            res.send(
                util.inspect(
                    {
                        caches: this.queue.cache.data,
                        defaultTtl: (this.queue.locks.defaultTtl = 10 * 60 * 1000),
                        locks: this.queue.locks.locks,
                        zones: this.queue.locks.zones,
                        lockOwners: this.queue.locks.lockOwners,
                        nextTtlCheck: this.queue.locks.nextTtlCheck || false,
                        counters: internalCounters.list()
                    },
                    false,
                    22
                )
            );

            return next();
        });

        // Returns message info in queue
        this.server.get('/internals/clear-counters', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }

            res.setHeader('content-type', 'text/plain; charset=utf-8');

            internalCounters.clear();

            res.send(
                util.inspect(
                    {
                        counters: internalCounters.list()
                    },
                    false,
                    22
                )
            );

            return next();
        });

        // list queued recipients for a zone
        this.server.get('/suppressionlist', (req, res, next) => {
            if (!this.queue) {
                res.json(500, {
                    error: 'Service not yet started'
                });
                return next();
            }

            this.queue.mongodb
                .collection('suppressionlist')
                .find({})
                .sort({
                    created: -1
                })
                .toArray((err, suppressed) => {
                    if (err) {
                        res.json(500, {
                            error: 'Database error: ' + err.message
                        });
                        return next();
                    }
                    res.json({
                        suppressed: (suppressed || []).map(entry => {
                            let result = {
                                id: entry._id.toString(),
                                created: entry.created
                            };
                            if (entry.address) {
                                result.address = entry.address;
                            }
                            if (entry.domain) {
                                result.domain = entry.domain;
                            }
                            return result;
                        })
                    });
                    next();
                });
        });

        this.server.post('/suppressionlist', (req, res, next) => {
            let address = (req.params.address || '').trim().toLowerCase();
            let domain = (req.params.domain || '').trim().toLowerCase();

            let entry = {
                created: new Date()
            };

            if (address) {
                entry.address = addressTools.normalizeAddress(address);
            }

            if (domain) {
                entry.domain = addressTools.normalizeDomain(domain);
            }

            if (!address && !domain) {
                res.json({
                    error: 'No address or domain defined'
                });
                return next();
            }

            this.queue.mongodb.collection('suppressionlist').insertOne(entry, (err, result) => {
                if (err) {
                    res.json({
                        error: 'Database error: ' + err.message
                    });
                    return next();
                }
                res.json({
                    suppressed: {
                        id: result.insertedId,
                        address: entry.address,
                        domain: entry.domain
                    }
                });
                next();
            });
        });

        this.server.del('/suppressionlist', (req, res, next) => {
            let id = (req.params.id || '').trim().toLowerCase();
            if (!/^[a-f0-9]{24}$/.test(id)) {
                res.json({
                    error: 'Invalid entry ID'
                });
                return next();
            }

            this.queue.mongodb.collection('suppressionlist').deleteOne(
                {
                    _id: new ObjectId(id)
                },
                err => {
                    if (err) {
                        res.json({
                            error: 'Database error: ' + err.message
                        });
                        return next();
                    }

                    res.json({
                        deleted: id
                    });
                    next();
                }
            );
        });

        this.server.get('/metrics', async (req, res) => {
            res.setHeader('Content-Type', promClient.register.contentType);
            await promClient.register
                .metrics()
                .then(metrics => res.send(metrics))
                .catch(err => {
                    log.error('API', err);
                    try {
                        res.statusCode = 500;
                        res.end('error: ' + err.message);
                    } catch (e) {
                        // ignore
                    }
                });
        });
    }
}

module.exports = APIServer;
