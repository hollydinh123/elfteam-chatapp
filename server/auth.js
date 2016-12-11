'use strict';

const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const async = require('async');
const encod = 'base64';
const hmac_alg = 'sha256';
// for testing and dev, load keys from package.json
const jwt_key = require('./package.json').jwt_key;
const client_hmac_key = require('./package.json').client_hmac_key;
const client_tag = require('./package.json').client_tag;

var db = levelup(path.join(__dirname, '.db'), {valueEncoding: 'json'});

function verify_client_tag(tag, cb) {  
  const hmac = crypto.createHmac('sha256', client_hmac_key);
  var computed_tag;
  if (!tag) {
    return cb(new Error('null tag'));
  } else {
    hmac.update(tag, encod);
    computed_tag = hmac.digest(encod);
    if (!crypto.timingSafeEqual(Buffer.from(computed_tag, encod), Buffer.from(client_tag, encod))) {
      return cb(new Error('invalid client tag'));
    } else {
      return cb();
    }
  }
}

function _create_tok(username, cb) { 
  jwt.sign({
    iat: new Date().getTime(),
    exp: Math.floor(new Date().getTime()/1000)+(60*30),
    iss: 'elfocrypt-server',
    sub: username
  }, Buffer.from(jwt_key, encod), {algorithm: 'HS256'}, (er, tok) => {
    if (er) return cb(er);
    return cb(null, tok);
  });
}

function verify_tok(token, cb) {
  async.waterfall([
    function(callback) {
      jwt.verify(token, Buffer.from(jwt_key, encod), {algorithms: ['HS256']}, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      if (decod && decod.iss && decod.iss === 'elfocrypt-server' && decod.sub) {
        db.get(decod.sub, (er) => {
          if (er) return callback(er);
          return callback(null, decod);
        });
      } else {
        return callback(new Error('invalid token'));
      }
    }
  ], (er, decod) => {
    if (er) return cb(er);
    return cb(null, decod);
  });
}

function init_register(usern, cb) {  
  db.get(usern, (er) => {
    if (!er) {
      return cb(new Error(`'${usern}' already taken. Please choose another one.`));
    } else {
      return cb();
    }
  });
}

function register(usern, user_pubkey, cb) {
  async.waterfall([
    function(callback) {
      init_register(usern, (er) => {
        if (er) return callback(er);
        return callback();
      });
    },
    function(callback) {  
      db.put(usern, {pub: user_pubkey, unread: []}, (er) => {
        if (er) return callback(er);
        console.log(`${usern} saved to db successfully`);
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function init_login(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(new Error(`'${usern}' not found`));
        return callback(null, user);
      });
    },
    function(user, callback) {
      var challenge = crypto.randomBytes(32).toString(encod);
      user.challenge = challenge;
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, challenge);
      });
    }
  ], (er, challenge) => {
    if (er) return cb(er);
    return cb(null, challenge);
  });
}

function login(usern, challenge_back, cb) { 
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(new Error(`'${usern}' not found`));
        return callback(null, user);
      });
    },
    function(user, callback) {
      var chunk, dec_challenge, hmac, hmac_key, tag, computed_tag, enc_challenge;
      try {
        chunk = challenge_back.split('&');
        hmac_key = crypto.publicDecrypt(Buffer.from(user.pub, encod).toString(), Buffer.from(chunk[0], encod));
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        tag = Buffer.from(chunk[1], encod);
        enc_challenge = Buffer.from(chunk[2], encod);
        hmac.update(enc_challenge);
        computed_tag = hmac.digest();
        if (!crypto.timingSafeEqual(computed_tag, tag)) {
          return callback(new Error(`'${usern}' not verified. Invalid tag.`));
        } else {
          dec_challenge = crypto.publicDecrypt(Buffer.from(user.pub, encod).toString(), enc_challenge);
          if (!crypto.timingSafeEqual(dec_challenge, Buffer.from(user.challenge, encod))) {
            return callback(new Error(`'${usern}' not verified. Invalid challenge handshake.`));
          } else {
            user.challenge = null;
            db.put(usern, user, (er) => {
              if (er) return callback(er);
              return callback();
            });
          }
        }
      } catch(er) {
        return callback(er);
      }
    },
    function(callback) {
      _create_tok(usern, (er, tok) => {
        if (er) return callback(er);
        return callback(null, tok);
      });
    }
  ], (er, tok) => {
    if (er) return cb(er);
    return cb(null, tok);
  });
}

function send_frd_req(sender, rec, pubtag, cb) {
  db.get(rec, (er, user) => {
    if (er) return cb(er);
    user.frd_req = {sen: sender, pubtag: pubtag};
    db.put(rec, user, (er) => {
      if (er) return cb(er);
      return cb();
    });
  });
}

function send_frd_rej(usern, rec, cb) {
  async.waterfall([
    function(callback) {
      db.get(rec, (er, user) => {
        if (er) return callback(er);
        user.frd_rej = usern;
        db.put(rec, user, (er) => {   
          if (er) return callback(er);
          return callback();
        });
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function fetch_frd_req(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user, user.frd_req);
      });
    },
    function(user, frd_req, callback) {
      user.frd_req = {};
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, frd_req);
      });
    }
  ], (er, frd_req) => {
    if (er) return cb(er);
    return cb(null, frd_req);
  });
}

function fetch_frd_rej(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user, user.frd_rej);
      });
    },
    function(user, frd_rej, callback) {
      user.frd_rej = '';  
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, frd_rej);
      });
    }
  ], (er, frd_rej) => {
    if (er) return cb(er);
    return cb(null, frd_rej);
  });
}

function handle_msg(sender, dat, cb) {
  async.waterfall([
    function(callback) {
      db.get(dat.rec, (er, user) => {
        if (er) return callback(er);
        user.unread.push({sen: sender, msg: dat.msg, time: dat.time});
        return callback(null, user);
      });
    },
    function(user, callback) {
      db.put(dat.rec, user, (er) => {
        if (er) return callback(er);
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function handle_group_msg(sender, dat, cb) {
  async.each(dat.members, (member, callback) => {
    async.waterfall([
      function(callb) {
        db.get(member, (er, user) => {
          if (er) return callb(er);
          user.unread.push({sen: sender, msg: dat.msg, time: dat.time, gname: dat.name});
          return callb(null, user);
        });
      },
      function(user, callb) {
        db.put(member, user, (er) => {
          if (er) return callb(er);
          return callb();
        });
      }
    ], (er) => {
      if (er) return callback(er);
      return callback();
    });
  }, (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function fetch_unread(usern, cb) {
  db.get(usern, (er, user) => {
    if (er) return cb(er);
    return cb(null, user.unread);
  });
}

function clear_unread(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user);
      });
    },
    function(user, callback) {
      user.unread.splice(0, user.unread.length);
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function check_gchat(name, cb) {
  async.waterfall([
    function(callback) {
      var valid = true;
      db.get('groups', (er, groups) => {
        if (er) {
          var emp = [];
          db.put('groups', emp, (er) => {
            if (er) return callback(er);
            return callback(null, valid);
          });
        } else {
          groups.forEach((group) => {
            if (group.name === name) valid = false;
          });
          return callback(null, valid);
        }
      });
    },
    function(valid, callback) {
      if (!valid) return callback(new Error(`'${name}' already taken. Please choose another one.`));
      return callback();
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function create_gchat(sender, dat, cb) {
  async.waterfall([
    function(callback) {
      db.get('groups', (er, groups) => {
        if (er) return callback(er);
        return callback(null, groups);
      });
    },
    function(groups, callback) {
      groups.push({name: dat.name, admin: sender});
      db.put('groups', groups, (er) => {
        if (er) return callback(er);
        return callback();
      });
    },
    function(callback) {
      if (dat.members.length > 0) {
        async.each(dat.members, (member, callb) => {
          if (member !== sender) {
            db.get(member, (er, user) => {
              if (er) return callb(er);
              user.gchat_req = {name: dat.name, admin: sender, members: dat.members, key: dat.key, sig: dat.sig};
              db.put(member, user, (er) => {
                if (er) return callb(er);
                return callb();
              });
            });
          } else {
            return callb();
          }
        }, (er) => {
          if (er) return callback(er);
          return callback();
        });
      } else {
        return callback();
      }
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function del_gchat(admin, gname, members, cb) {
  async.waterfall([
    function(callback) {
      db.get('groups', (er, groups) => {
        if (er) return callback(er);
        return callback(null, groups);
      });
    },
    function(groups, callback) {
      var index = -1;
      groups.forEach((group, i) => {
        if (group.name === gname && group.admin === admin) {
          index = i;
        }
      });
      return callback(null, groups, index);
    },
    function(groups, index, callback) {
      if (index !== -1) {
        groups.splice(index, 1);
        db.put('groups', groups, (er) => {
          if (er) return callback(er);
          return callback();
        });
      } else {
        return callback();
      }
    },
    function(callback) {
      if (members.length > 0) {
        async.each(members, (member, callb) => {
          db.get(member, (er, user) => {
            if (er) return callb(er);
            user.gchat_del = {gname: gname, admin: admin};
            db.put(member, user, (er) => {
              if (er) return callb(er);
              return callb();
            });
          });
        }, (er) => {
          if (er) return callback(er);
          return callback();
        });
      } else {
        return callback();
      }
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function fetch_gchat_del(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user, user.gchat_del);
      });
    },
    function(user, gchat_del, callback) {
      user.gchat_del = {};
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, gchat_del);
      });
    }
  ], (er, gchat_del) => {
    if (er) return cb(er);
    return cb(null, gchat_del);
  });
}

function fetch_gchat_req(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user, user.gchat_req);
      });
    },
    function(user, gchat_req, callback) {
      user.gchat_req = {};
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, gchat_req);
      });
    }
  ], (er, gchat_req) => {
    if (er) return cb(er);
    return cb(null, gchat_req);
  });
}

function fetch_gchat_rej(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user, user.gchat_rej);
      });
    },
    function(user, gchat_rej, callback) {
      user.gchat_rej = {};  
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, gchat_rej);
      });
    }
  ], (er, gchat_rej) => {
    if (er) return cb(er);
    return cb(null, gchat_rej);
  });
}

function send_gchat_rej(usern, dat, cb) {
  db.get(dat.rec, (er, user) => {
    if (er) return cb(er);
    user.gchat_rej = {rejector: usern, gname: dat.gname};
    db.put(dat.rec, user, (er) => {
      if (er) return cb(er);
      return cb();
    });
  });
}

module.exports = {
  verify_client_tag: verify_client_tag,
  verify_tok: verify_tok,
  init_register: init_register,
  register: register,
  init_login: init_login,
  login: login,
  send_frd_req: send_frd_req,
  send_frd_rej: send_frd_rej,
  fetch_frd_req: fetch_frd_req,
  fetch_frd_rej: fetch_frd_rej,
  handle_msg: handle_msg,
  handle_group_msg: handle_group_msg,
  fetch_unread: fetch_unread,
  clear_unread: clear_unread,
  check_gchat: check_gchat,
  create_gchat: create_gchat,
  del_gchat: del_gchat,
  fetch_gchat_del: fetch_gchat_del,
  fetch_gchat_req: fetch_gchat_req,
  fetch_gchat_rej: fetch_gchat_rej,
  send_gchat_rej: send_gchat_rej
};