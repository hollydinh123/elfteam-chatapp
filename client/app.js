'use strict';

const path = require('path');
const electron = require('electron');
const {app, BrowserWindow, dialog, ipcMain} = electron;
const iconpath = path.join(__dirname, 'resources', 'appicon.png');
const auth = require('./auth.js');

const reg_index = `file://${__dirname}/views/reg.html`;
const login_index = `file://${__dirname}/views/login.html`;
const getfrd_index = `file://${__dirname}/views/get_frd_req.html`;
const sendfrd_index = `file://${__dirname}/views/send_frd_req.html`;
const main_index = `file://${__dirname}/views/main_win.html`;
const gchat_index = `file://${__dirname}/views/gchat.html`;

var reg_win = null;
var login_win = null;
var sendfrd_win = null;
var getfrd_win = null;
var main_win = null;
var gchat_win = null;

var frd_req_timer;
var frd_rej_timer;
var unread_timer;
var gchat_req_timer;
var gchat_rej_timer;
var gchat_del_timer;
var exp = 0;

function clear_timers() {
  clearInterval(frd_req_timer);
  clearInterval(frd_rej_timer);
  clearInterval(unread_timer);
  clearInterval(gchat_req_timer);
  clearInterval(gchat_del_timer);
}

function close_app() {
  if (login_win !== null) {
    login_win.close();
  } 
  if (getfrd_win !== null) {
    getfrd_win.close();
  }
  if (sendfrd_win !== null) {
    sendfrd_win.close();
  } 
  if (gchat_win !== null) {
    gchat_win.close();
  }
  if (main_win !== null) {
    main_win.close();
  }
  clear_timers();
  app.quit();
}

function showerr(er) {
  console.log(er);
  if (er.message === 'jwt expired') {
    if (exp === 0) {
      exp = 1;
      var ans = dialog.showMessageBox({
        type: 'info',
        title: 'Authentication Token Expired',
        message: `\nYour authentication token is expired. What do you like to do?`,
        buttons: ['quit', 'relogin']
      });
      if (ans === 0) {
        close_app();
      } else {
        app.relaunch();
        close_app();
      }
    }
  } else {
    dialog.showMessageBox({
      type: 'error',
      title: 'elfocrypt error',
      message: `\n${er.message}`,
      buttons: ['ok']
    });
  }
}

function showinfo(info) {
  dialog.showMessageBox({
    type: 'info',
    title: 'elfocrypt',
    message: `\n${info}`,
    buttons: ['ok']
  });
}

function set_frd_req_timer() {
  frd_req_timer = setInterval(() => {
    auth.fetch_frd_req((er, sen) => {
      var ans;
      if (er) {
        showerr(er);
      }
      if (sen) {
        ans = dialog.showMessageBox({
          type: 'info',
          title: 'friend request',
          message: `\n${sen} wants to add you as a friend. Do you accept?`,
          buttons: ['no', 'yes']
        });
        if (ans === 0) {
          auth.send_frd_rej(sen, (er) => {
            if (er) {
              showerr(er);
            } else {
              showinfo(`A reject response sent to ${sen}`);
              main_win.focus();
            }
          });
        } else {
          load_verify_frd();
        }
      }
    });
  }, 7000);
}

function set_frd_rej_timer() {
  frd_rej_timer = setInterval(() => {
    auth.fetch_frd_rej((er, rej) => {
      if (er) {
        showerr(er);
      }
      if (rej) {
        showinfo(`${rej} rejected your friend request`);
      }
    });
  }, 7000);
}

function set_unread_timer() {
  unread_timer = setInterval(() => {
    auth.fetch_unread((er, unread) => {
      if (er) {
        showerr(er);
      }
      if (unread) {    
        main_win.webContents.send('fetch-unread-success', unread);
      }
    });
  }, 7000);
}

function set_gchat_req_timer() {
  gchat_req_timer = setInterval(() => {
    auth.fetch_gchat_req((er, dat) => {
      var ans;
      if (er) {
        showerr(er);
      }
      if (dat && dat.sender && dat.gname) {
        ans = dialog.showMessageBox({
          type: 'info',
          title: 'friend request',
          message: `\n${dat.sender} wants to add you to the group '${dat.gname}'. Do you accept?`,
          buttons: ['no', 'yes']
        });
        if (ans === 0) { // reject the gchat
          auth.send_gchat_rej(dat, (er) => {
            if (er) {
              showerr(er);
            } else {
              showinfo(`A reject response sent to ${dat.sender}`);
              main_win.focus();
            }
          });
        } else {
          auth.verify_gchat_req((er) => {
            if (er) {
              showerr(er);
            } else {
              showinfo(`group ${dat.gname} verified and added successfully`);
              main_win.reload();
            }
          });
        }
      }
    });
  }, 7000);
}

function set_gchat_rej_timer() {
  gchat_rej_timer = setInterval(() => {
    auth.fetch_gchat_rej((er, rej) => {
      if (er) {
        showerr(er);
      }
      if (rej && rej.rejector && rej.name) {
        showinfo(`${rej.rejector} rejected your group '${rej.gname}' request`);
      }
    });
  }, 7000);
}

function set_gchat_del_timer() {
  gchat_del_timer = setInterval(() => {
    auth.fetch_gchat_del((er, del) => {
      if (er) {
        showerr(er);
      }
      if (del) {
        showinfo(`The group '${del.gname}' deleted by ${del.admin}`);
        main_win.reload();
      }
    });
  }, 7000);
}

function set_timers() {
  set_frd_req_timer();
  set_frd_rej_timer();
  set_unread_timer();
  set_gchat_req_timer();
  set_gchat_rej_timer();
  set_gchat_del_timer();
}

var wins = {
  register: function() {
    reg_win = new BrowserWindow({
      width: 600,
      height: 300,
      'min-width': 400,
      'min-height': 200,
      icon: iconpath
    });

    reg_win.on('closed', () => {
      reg_win = null;
    });

    reg_win.loadURL(reg_index);
    reg_win.show();
  },
  login: function() {
    login_win = new BrowserWindow({
      width: 600,
      height: 300,
      'min-width': 400,
      'min-height': 200,
      icon: iconpath
    });

    login_win.on('closed', () => {
      login_win = null;
    });

    login_win.loadURL(login_index);
    login_win.show();
  },
  sendfrd: function() {
    sendfrd_win = new BrowserWindow({
      width: 700,
      height: 500,
      'min-width': 400,
      'min-height': 200,
      icon: iconpath
    });
    sendfrd_win.on('closed', () => {
      sendfrd_win = null;
    });
    sendfrd_win.loadURL(sendfrd_index);
    sendfrd_win.show();
  },
  getfrd: function() {
    getfrd_win = new BrowserWindow({
      width: 700,
      height: 500,
      'min-width': 400,
      'min-height': 200,
      icon: iconpath
    });
    getfrd_win.on('closed', () => {
      getfrd_win = null;
    });
    getfrd_win.loadURL(getfrd_index);
    getfrd_win.show();
    getfrd_win.focus();
  },
  gchat: function() {
    gchat_win = new BrowserWindow({
      width: 1000,
      height: 600,
      'min-width': 400,
      'min-height': 200,
      icon: iconpath
    });
    gchat_win.on('closed', () => {
      gchat_win = null;
    });

    gchat_win.loadURL(gchat_index);
    gchat_win.show();
  },
  main: function() {
    main_win = new BrowserWindow({
      width: 1000,
      height: 600,
      'min-width': 400,
      'min-height': 200,
      icon: iconpath
    });

    main_win.on('closed', () => {
      main_win = null;
    });
    set_timers();
    main_win.loadURL(main_index);
    main_win.show();
  }
};

function load_reg() {
  wins.register();
}

function load_login() { 
  wins.login();
}

function load_main() {
  wins.main();
}

function load_sendfrd() {
  wins.sendfrd();
}

function load_verify_frd() {
  wins.getfrd();
}

function load_gchat() {
  wins.gchat();
}

function init() {
  auth.is_reg_user((y) => {
    if (y) {
      load_login();
    } else {
      load_reg();
    }
  });
}

app.on('ready', () => {
  init();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {  
    app.quit();
  }
});

app.on('activate', () => {
  if (login_win === null) {
    init();
  }
});

ipcMain.on('load-sendfrd', () => {
  load_sendfrd();
});

ipcMain.on('load-gchat', () => {
  load_gchat();
});

ipcMain.on('reg-err', (event, err) => {
  showerr(err);
  reg_win.reload();
});

ipcMain.on('login-err', (event, err) => {
  showerr(err);
  login_win.reload();
});

ipcMain.on('sendfrd-err', (event, err) => {
  showerr(err);
  sendfrd_win.reload();
});

ipcMain.on('getfrd-err', (event, err) => {
  showerr(err);
  getfrd_win.reload();
});

ipcMain.on('gchat-err', (event, err) => {
  showerr(err);
  gchat_win.reload();
});

ipcMain.on('main-err', (event, err) => {
  showerr(err);
  main_win.reload();
});

ipcMain.on('request-reg', (ev, usern) => {
  if (usern) {
    auth.register(usern, (er) => {
      if (er) {
        showerr(er);
        reg_win.reload();
      } else {
        load_login();
        reg_win.close();
      }
    });
  } else {
    showerr(new Error('invalid username'));
  }
});

ipcMain.on('request-login', (ev, usern) => {
  if (usern) {
    auth.login(usern, (er) => {
      if (er) {
        showerr(er);
        login_win.reload();
      } else {
        load_main();
        login_win.close();
      }
    });
  } else {
    showerr(new Error('invalid username'));
  }
});

ipcMain.on('send-frd-req', (ev, dat) => {
  if (dat.frd_un && dat.sec) {
    auth.send_frd_req(dat.frd_un, dat.sec, (er) => {
      if (er) {
        showerr(er);
        sendfrd_win.reload();
      } else {
        sendfrd_win.close();
      }
    });
  } else {
    showerr(new Error('invalid username/secret'));
    main_win.reload();
  }
});

ipcMain.on('verify-frd-req', (ev, dat) => {
  if (dat.frd_un && dat.sec) {
    auth.verify_frd_req(dat.frd_un, dat.sec, (er) => {
      if (er) {
        showerr(er);
      } else {
        showinfo(`${dat.frd_un} verified and added successfully`);
        getfrd_win.close();
        main_win.reload();
      }
    });
  } else {
    showerr(new Error('null friend username and/or shared secret'));
  }
});

ipcMain.on('frd-ls', (ev) => {
  auth.get_frds((er, frds) => {
    if (er) {
      showerr(er);
      if (main_win !== null) {
        main_win.reload();
      }
    }
    if (frds) {
      ev.sender.send('frd-ls-success', frds);
    }
  });
});

ipcMain.on('send-msg', (ev, dat) => {
  if (dat.msg && dat.receiver) {
    auth.send_msg(dat.msg, dat.receiver, (er, res) => {
      if (er) {
        showerr(er);
        if (main_win !== null) {
          main_win.reload();
        }
      }
      if (res) {
        ev.sender.send('send-msg-success', res);
      }
    });
  } else {
    showerr(new Error('null message and/or receiver'));
  }
});

ipcMain.on('send-create-gchat', (ev, dat) => {
  auth.create_gchat(dat.name, dat.members, (er) => {
    if (er) {
      showerr(er);
    } else {
      showinfo('group chat invitation sent successfully');
      main_win.reload();
      gchat_win.close();
    }
  });
});

ipcMain.on('is-group-admin', (ev, gname) => {
  auth.is_group_admin(gname.split(' (G)')[0], (er, result) => {
    if (er) {
      showerr(er);
    } else {
      ev.returnValue = result;
    }
  });
});

ipcMain.on('get-gmembers', (ev, gname) => {
  auth.get_gmembers(gname.split(' (G)')[0], (er, members) => {
    if (er) {
      showerr(er);
    } else {
      ev.returnValue = members;
    }
  });
});

ipcMain.on('delete-gchat', (ev, name) => {
  var gname = name.split(' (G)')[0];
  var ans = dialog.showMessageBox({
    type: 'info',
    title: 'delete group chat',
    message: `\nAre you sure you want to delete '${gname}'?`,
    buttons: ['no', 'yes']
  });
  if (ans === 0) {
    main_win.reload();
  } else {
    auth.rm_group(gname, (er) => {
      if (er) {
        showerr(er);
      } else {
        main_win.reload();
      }
    });
  }
});

process.on('uncaughtException', (er) => {
  console.log('unexp-err:', er);
  showerr(er);
  close_app();
});