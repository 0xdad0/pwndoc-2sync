'use strict';
require('./obsidian-stub');
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { __test: T } = require('../main.js');

function server(handler) {
    return new Promise(resolve => {
        const s = http.createServer(handler).listen(0, '127.0.0.1', () => resolve(s));
    });
}

test('pwndocApi GET returns datas', async () => {
    const s = await server((req, res) => res.end(JSON.stringify({ status: 'success', datas: { a: 1 } })));
    const base = `http://127.0.0.1:${s.address().port}`;
    assert.deepEqual(await T.pwndocApi(base, 'T', 'GET', '/api/x'), { a: 1 });
    s.closeAllConnections(); s.close();
});

test('pwndocApi PUT sends JSON body and JWT cookie', async () => {
    const s = await server((req, res) => {
        let b = '';
        req.on('data', c => b += c);
        req.on('end', () => res.end(JSON.stringify({ datas: { body: JSON.parse(b), cookie: req.headers.cookie, method: req.method } })));
    });
    const base = `http://127.0.0.1:${s.address().port}`;
    const r = await T.pwndocApi(base, 'T', 'PUT', '/api/x', { body: { k: 'v' } });
    assert.deepEqual(r, { body: { k: 'v' }, cookie: 'token= JWT T', method: 'PUT' });
    s.closeAllConnections(); s.close();
});

test('pwndocApi rejects with HTTP status on 500', async () => {
    const s = await server((req, res) => { res.statusCode = 500; res.end('boom'); });
    const base = `http://127.0.0.1:${s.address().port}`;
    await assert.rejects(T.pwndocApi(base, 'T', 'GET', '/api/x'), /HTTP 500/);
    s.closeAllConnections(); s.close();
});
