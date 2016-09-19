'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;

/**
 * get document elements by their ids
 */

var user_in = document.getElementById('usern');
var pass_in = document.getElementById('passw');
var login_btn = document.getElementById('login-btn');
var reg_link = document.getElementById('reg-link');

/**
 * load create account window on clicking
 * on 'create account' link
 */

reg_link.addEventListener('click', (event) => {
  event.preventDefault();
  ipc.send('load-reg');
});

/**
 * login button click listener
 */

login_btn.addEventListener('click', (ev) => { 
  ev.preventDefault();
  if (user_in.value !== null && pass_in.value !== null &&
    user_in.value !== '' && pass_in.value !== '') {
      ipc.send('request-login', {usern: user_in.value, passw: pass_in.value});
    } else {
      ipc.send('login-err', 'username/password cannot be null');
    }
});
