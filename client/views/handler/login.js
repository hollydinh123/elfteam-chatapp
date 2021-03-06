'use strict';

const electron = require('electron');
const ipc = electron.ipcRenderer;
var user_in = document.getElementById('usern');

document.getElementById('login-btn').addEventListener('click', (ev) => { 
  ev.preventDefault();
  if (user_in.value !== null && user_in.value !== '') {
    ipc.send('request-login', user_in.value);
  } else {
    ipc.send('login-err', 'username cannot be null');
  }
});
