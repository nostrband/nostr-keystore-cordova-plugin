var exec = require('cordova/exec');

const SERVICE_NAME = "NostrKeyStore";
const SIGN_EVENT = "signEvent";
const GET_PUBLIC_KEY = "getPublicKey";
const LIST_KEYS = "listKeys";
const ADD_KEY = "addKey";
const SELECT_KEY = "selectKey";
const EDIT_KEY = "editKey";
const SHOW_KEY = "showKey";
const DELETE_KEY = "deleteKey";

var NostrKeyStore = {

    signEvent: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, SIGN_EVENT, [msg]);
    },

    getPublicKey: function (success, error) {
        exec(success, error, SERVICE_NAME, GET_PUBLIC_KEY, []);
    },

    listKeys: function (success, error) {
        exec(success, error, SERVICE_NAME, LIST_KEYS, []);
    },

    addKey: function (success, error) {
        exec(success, error, SERVICE_NAME, ADD_KEY, []);
    },

    selectKey: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, SELECT_KEY, [msg]);
    },

    editKey: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, EDIT_KEY, [msg]);
    },

    showKey: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, SHOW_KEY, [msg]);
    },

    deleteKey: function (success, error, msg) {
        exec(success, error, SERVICE_NAME, DELETE_KEY, [msg]);
    }

};

document.addEventListener("deviceready", onDeviceReady, false)

function onDeviceReady() {
    let NostrKeyStore = {
        getPublicKey: function () {
            return new Promise((resolve, reject) => {
                cordova.plugins.NostrKeyStore.getPublicKey(
                    function (res) {
                        resolve(res.pubKey.replaceAll("\"", ""))
                    },
                    function (error) {
                        reject(error)
                    }
                )
            })
        },
        signEvent: function (msg) {
            return new Promise((resolve, reject) => {
                cordova.plugins.NostrKeyStore.signEvent(
                    function (res) {
                        resolve(res)
                    },
                    function (error) {
                        reject(error)
                    },
                    msg
                )
            })
        }
    }

    window.nostr = NostrKeyStore

    document.addEventListener("backbutton", function (e) {
        if (!window.history || JSON.stringify(window.history.state) === 'null') { //you check that there is nothing left in the history.
            e.preventDefault();
            navigator.app.exitApp();
        } else {
            window.history.back();
        }
    });
}

module.exports = NostrKeyStore;
