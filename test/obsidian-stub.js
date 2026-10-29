'use strict';
const Module = require('module');
const orig = Module._load;
const noop = class {};
Module._load = function (request, ...rest) {
    if (request === 'obsidian') {
        return {
            Plugin: noop, PluginSettingTab: noop, Setting: noop, FuzzySuggestModal: noop,
            SuggestModal: noop, Modal: noop, Notice: noop, normalizePath: p => p,
        };
    }
    return orig.call(this, request, ...rest);
};
