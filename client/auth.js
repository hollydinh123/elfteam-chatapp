'use strict';

const path = require('path');
const crypto = require('crypto');
const request = require('request');
const levelup = require('levelup');
const async = require('async');
const gen_rsakey = require('keypair');
const assign = require('deep-assign');
const uri = {
  init_reg: 'https://elfocrypt.me/init_reg',
  reg: 'https://elfocrypt.me/reg',
  init_login: 'https://elfocrypt.me/init_login',
  login: 'https://elfocrypt.me/login',
  send_frd_req: 'https://elfocrypt.me/send_frd_req',
  send_frd_rej: 'https://elfocrypt.me/send_frd_rej',
  fetch_frd_req: 'https://elfocrypt.me/fetch_frd_req',
  fetch_frd_rej: 'https://elfocrypt.me/fetch_frd_rej',
  msg: 'https://elfocrypt.me/msg',
  g_msg: 'https://elfocrypt.me/g_msg',
  unread: 'https://elfocrypt.me/unread',
  check_gchat: 'https://elfocrypt.me/check_gchat',
  create_gchat: 'https://elfocrypt.me/create_gchat',
  del_gchat: 'https://elfocrypt.me/del_gchat',
  fetch_gchat_req: 'https://elfocrypt.me/fetch_gchat_req',
  fetch_gchat_rej: 'https://elfocrypt.me/fetch_gchat_rej',
  fetch_gchat_del: 'https://elfocrypt.me/fetch_gchat_del',
};
const encod = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const client_key = require(path.join(__dirname, 'package.json')).clientkey;
var db = levelup(path.join(__dirname, '.db'), {valueEncoding: 'binary'});

function _request_reg(url, dat, cb) {
  var server_res;
  request.post({url: url, headers: {authorization: client_key}, rejectUnauthorized: true, form: dat}, (er, res, body) => {
    if (er) {
      console.log(er);
      return cb(er);
    }
    try {
      server_res = JSON.parse(body);
    } catch(er) {
      console.log(er);
      return cb(er);
    }
    if (server_res.err) {
      console.log(server_res);
      return cb(new Error(server_res.err));
    }
    return cb(null, server_res);
  });
}

function _encrypt_challenge(challenge, cb) {
  async.waterfall([
    function(callback) {
      db.get('privkey', (er, privkey) => {
        if (er) return callback(er);
        return callback(null, privkey);
      }); 
    },
    
function(privkey, callback) {
      var enc_challenge, tag, hmac, hmac_key, enc_hmac_key;
      try {
        hmac_key = crypto.randomBytes(32);
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        enc_challenge = crypto.privateEncrypt(privkey, Buffer.from(challenge, encod));
        enc_hmac_key = crypto.privateEncrypt(privkey, hmac_key);
        hmac.update(enc_challenge);
        tag = hmac.digest();
        return callback(null, `${enc_hmac_key.toString(encod)}&${tag.toString(encod)}&${enc_challenge.toString(encod)}`);
      } catch(er) {
        return callback(er);
      }
    }
  ], (er, enc_dat) => {
    if (er) return cb(er);
    return cb(null, enc_dat);
  });
}

function register(usern, cb) {
  async.waterfall([
    function(callback) {
      _request_reg(uri.init_reg, {usern: usern}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },

function(callback) {
      var rsa = gen_rsakey();
      db.put('privkey', rsa.private, (er) => {
        if (er) return callback(er);
        return callback(null, rsa.public);
      });
    },

function(pubkey, callback) {
      _request_reg(uri.reg, {usern: usern, pub: Buffer.from(pubkey).toString(encod)}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },

 function(callback) {
      var user_rsa = gen_rsakey();
      return callback(null, user_rsa);
    },
    function(userkeys, callback) {
      var frds = [];
      var groups = [];
      db.batch()
        .put('name', usern)
        .put('priv', userkeys.private)
        .put('pub', userkeys.public)
        .put('frds', JSON.stringify(frds))
        .put('groups', JSON.stringify(groups))
        .write((er) => {
          if (er) return callback(er);
          console.log(`${usern} saved to local db successfully`);
          return callback();
        });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}
function(userkeys, callback) {
      var frds = [];
      var groups = [];
      db.batch()
        .put('name', usern)
        .put('priv', userkeys.private)
        .put('pub', userkeys.public)
        .put('frds', JSON.stringify(frds))
        .put('groups', JSON.stringify(groups))
        .write((er) => {
          if (er) return callback(er);
          console.log(`${usern} saved to local db successfully`);
          return callback();
        });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}
function login(usern, cb) {
  async.waterfall([
    function(callback) {
      _request_reg(uri.init_login, {usern: usern}, (er, res) => {
        if (er) return callback(er);
        if (res.challenge) {
          return callback(null, res.challenge);
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(challenge, callback) {
      _encrypt_challenge(challenge, (er, enc_challenge) => {
        if (er) return callback(er);
        return callback(null, enc_challenge);
      });
    },
    function(enc_challenge, callback) {
      _request_reg(uri.login, {usern: usern, challenge_back: enc_challenge}, (er, res) => {
        if (er) return callback(er);
        if (res.token) {
          return callback(null, res.token);
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(token, callback) {
      db.put('tok', token, (er) => {
        if (er) return callback(er);
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function _req(opts, cb) {
  async.waterfall([
    function(callback) {
      db.get('tok', (er, tok) => {
        if (er) return callback(er);
        return callback(null, tok);
      });
    },
    function(tok, callback) {
      var server_res;
      opts = assign(opts, {headers: {authorization: tok}, rejectUnauthorized: true});
      request.post(opts, (er, res, body) => {
        if (er) return callback(er);
        try {
          server_res = JSON.parse(body);
        } catch(er) {
          return callback(er);
        }
        if (server_res.err) return callback(new Error(server_res.err));
        return callback(null, server_res);
      });
    }
  ], (er, server_res) => {
    if (er) return cb(er);
    return cb(null, server_res);
  });
}

function _add_frd(frd_username, frd_key, cb) {
  var frds;
  db.get('frds', (er, friends) => {
    if (er) return cb(er);
    try {
      frds = JSON.parse(friends);
    } catch(er) {
      return cb(er);
    }
    frds.push({name: frd_username, key: frd_key});
    db.put('frds', JSON.stringify(frds), (er) => {
      if (er) return cb(er);
      return cb();
    });
  });
}

function get_frds(cb) {
  async.waterfall([
    function(callback) {
      db.get('frds', (er, friends) => {
        if (er) return callback(er);
        try {
          return callback(null, JSON.parse(friends));
        } catch(er) {
          return callback(er);
        }
      });
    },
    function(frds, callback) {
      var names = [];
      if (frds.length > 0) {
        frds.forEach((frd) => {
          if (names.indexOf(frd.name) === -1) {
            names.push(frd.name);
          }
        });
      }
      return callback(null, names);
    },
    function(names, callback) {
      db.get('groups', (er, groups) => {
        var grps;
        if (er) return callback(er);
        try {
          grps = JSON.parse(groups);
        } catch(er) {
          return callback(er);
        }
        return callback(null, names, grps);
      });
    },
    function(names, groups, callback) {
      if (groups.length > 0) {
        groups.forEach((group) => {
          if (names.indexOf(`${group.name} (G)`) === -1) {
            names.push(`${group.name} (G)`);
          }
        });
      }
      return callback(null, names);
    }
  ], (er, names) => {
    if (er) return cb(er);
    return cb(null, names);
  });
}

function _get_frd_pubkey(frd_username, cb) {
  async.waterfall([
    function(callback) {
      db.get('frds', (er, friends) => {
        if (er) return callback(er);
        try {
          return callback(null, JSON.parse(friends));
        } catch(er) {
          return callback(er);
        }
      });
    },
    function(frds, callback) {
      var frd_pubkey;
      frds.forEach((frd) => {
        if (frd.key && frd.name === frd_username) {
          frd_pubkey = frd.key;
        }
      });
      return callback(null, frd_pubkey);
    }
  ], (er, frd_pubkey) => {
    if (er) return cb(er);
    return cb(null, frd_pubkey);
  });
}

function verify_frd_req(frd, sec, cb) {
  async.waterfall([
    function(callback) {
      db.get('frd_req', (er, freq) => {
        var req;
        if (er) return callback(er);
        try {
          req = JSON.parse(freq);
        } catch(er) {
          return callback(er);
        }
        return callback(null, req);
      });
    },
    function(req, callback) {
      if (!req.sen || !req.pubtag) {
        return callback(new Error('invalid friend request'));
      } else {
        if (req.sen !== frd) {
          return callback(new Error('invalid friend request'));
        } else {
          return callback(null, req);
        }
      }
    },
    function(req, callback) {
      var chunk, frd_pubkey, hash, hmac, hmac_key, computed_tag, tag;
      try {
        hash = crypto.createHash('sha256');
        hash.update(sec);
        hmac_key = hash.digest();
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        chunk = req.pubtag.split('&');
        tag = chunk[0];
        frd_pubkey = Buffer.from(chunk[1], encod).toString();
        hmac.update(frd_pubkey);
        computed_tag = hmac.digest(encod);
        if (computed_tag !== tag) {
          return callback(new Error('invalid signature'));
        } else {
          return callback(null, chunk[1]);
        }
      } catch(er) {
        return callback(er);
      }
    },
    function(frd_pubkey, callback) {
      _add_frd(frd, frd_pubkey, (er) => {
        if (er) return callback(er);
        db.del('frd_req', (er) => {
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

function send_frd_req(frd_un, sec, cb) {
  async.waterfall([
    function(callback) {
      db.get('pub', (er, pubkey) => {
        if (er) return callback(er);
        return callback(null, pubkey);
      });
    },
    function(pubkey, callback) {
      var hash, hmac, hmac_key, tag;
      try {
        hash = crypto.createHash('sha256');
        hash.update(sec);
        hmac_key = hash.digest();
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        hmac.update(pubkey);
        tag = hmac.digest(encod);
        return callback(null, `${tag}&${Buffer.from(pubkey).toString(encod)}`);
      } catch(er) {
        return callback(er);
      }
    },
    function(pubtag, callback) {
      _req({url: uri.send_frd_req, form: {rec: frd_un, pubtag: pubtag}}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function send_frd_rej(rec, cb) {    
  _req({url: uri.send_frd_rej, form: {rec: rec}}, (er, res) => {
    if (er) return cb(er);
    if (res.info && res.info === 'ok') {
      return cb();
    } else {
      return cb(new Error('no proper response received from the server'));
    }
  });
}

function fetch_frd_req(cb) {
  async.waterfall([
    function(callback) {
      _req({url: uri.fetch_frd_req}, (er, res) => {
        if (er) return callback(er);
        return callback(null, res);
      });
    },
    function(res, callback) {
      if (res && res.frd_req && res.frd_req.sen && res.frd_req.pubtag) {
        db.put('frd_req', JSON.stringify(res.frd_req), (er) => {
          if (er) return callback(er);
          return callback(null, res.frd_req.sen);
        });
      } else {
        return callback();
      }
    }
  ], (er, sen) => {
    if (er) return cb(er);
    return cb(null, sen);
  });
}

function fetch_frd_rej(cb) {
  _req({url: uri.fetch_frd_rej}, (er, res) => {
    if (er) return cb(er);
    if (res && res.frd_rej) {
      return cb(null, res.frd_rej);
    } else {
      return cb();
    }
  });
}

function _encrypt(dat, rec_pubkey, cb) { 
  async.waterfall([
    function(callback) {
      var dat_key, hmac_key, iv, hmac, tag, keys_encrypted, cipher, cipher_dat;
      try {
        dat_key = crypto.randomBytes(32);
        hmac_key = crypto.randomBytes(32);
        iv = crypto.randomBytes(16);
        hmac = crypto.createHmac(hmac_alg, hmac_key);

        cipher = crypto.createCipheriv(alg, dat_key, iv);
        cipher_dat = Buffer.concat([cipher.update(dat), cipher.final()]);
        keys_encrypted = crypto.publicEncrypt(rec_pubkey, Buffer.from(`${dat_key.toString(encod)}&${hmac_key.toString(encod)}`));

        hmac.update(keys_encrypted);
        hmac.update(cipher_dat);
        hmac.update(iv);
        tag = hmac.digest();
        return callback(null, `${keys_encrypted.toString(encod)}&${cipher_dat.toString(encod)}&${iv.toString(encod)}&${tag.toString(encod)}`);
      } catch(er) {
        return callback(er);
      }
    }
  ], (er, enc_dat) => {
    if (er) return cb(er);
    return cb(null, enc_dat);
  });
}

function _decrypt(cipher_chunk, privkey, cb) {
  async.waterfall([
    function(callback) {
      var chunk, keys_encrypted, keys_dec, cdat, iv, tag, dat_key, hmac_key, hmac, computed_tag, decipher, decrypted;
      try {
        chunk = cipher_chunk.split('&');
        keys_encrypted = Buffer.from(chunk[0], encod);
        cdat = Buffer.from(chunk[1], encod);
        iv = Buffer.from(chunk[2], encod);
        tag = chunk[3];

        keys_dec = crypto.privateDecrypt(privkey, keys_encrypted).toString().split('&');
        dat_key = Buffer.from(keys_dec[0], encod);
        hmac_key = Buffer.from(keys_dec[1], encod);

        hmac = crypto.createHmac(hmac_alg, hmac_key);
        hmac.update(keys_encrypted);
        hmac.update(cdat);
        hmac.update(iv);
        computed_tag = hmac.digest(encod);
        if (computed_tag !== tag) {
          return callback(new Error('invalid integrity tag'));
        } else {
          decipher = crypto.createDecipheriv(alg, dat_key, iv);
          decrypted = Buffer.concat([decipher.update(cdat), decipher.final()]);
          return callback(null, decrypted);
        }
      } catch(er) {
        return callback(er);
      }
    }
  ], (er, decrypted) => {
    if (er) return cb(er);
    return cb(null, decrypted) ;
  });
}

function _get_gkeys(gname, cb) {
  var keys = {};
  var grps;
  db.get('groups', (er, groups) => {
    if (er) return cb(er);
    try {
      grps = JSON.parse(groups);
    } catch(er) {
      return cb(er);
    }
    grps.forEach((group) => {
      if (group.name === gname) {
        keys = {
          priv: group.privkey,
          pub: group.pubkey
        };
      }
    });
    return cb(null, keys);
  });
}

function get_gmembers(gname, cb) {
  var members = [];
  db.get('name', (er, usern) => {
    if (er) return cb(er);
    db.get('groups', (er, groups) => {
      var grps;
      if (er) return cb(er);
      try {
        grps = JSON.parse(groups);
      } catch(er) {
        return cb(er);
      }
      grps.forEach((group) => {
        if (group.name === gname) {
          members = group.members;
        }
      });
      members.splice(members.indexOf(usern), 1);
      return cb(null, members);
    });
  });
}

function _send_group_msg(msg, gname, cb) {
  async.waterfall([
    function(callback) {
      _get_gkeys(gname, (er, keys) => {
        if (er) {
          return callback(er);
        }
        return callback(null, keys.pub);
      });
    },
    function(g_pubkey, callback) {
      _encrypt(Buffer.from(msg), g_pubkey, (er, enc_msg) => {
        if (er) return callback(er);
        return callback(null, enc_msg);
      });
    },
    function(enc_msg, callback) {
      get_gmembers(gname, (er, members) => {
        if (er) {
          return callback(er);
        }
        return callback(null, enc_msg, members);
      });
    },
    function(enc_msg, members, callback) {
      var d = new Date();
      var msgtime = `${d.getFullYear()}/${d.getMonth()}/${d.getDate()} ${d.getHours()}:${d.getMinutes()}`;
      _req({url: uri.g_msg, form: {gname: gname, msg: enc_msg, gmembers: JSON.stringify(members), time: msgtime}}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback(null, msgtime);
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(msgtime, callback) {
      db.get('name', (er, usern) => {
        if (er) return callback(er);
        return callback(null, {gname: gname, sen: usern, msg: msg, time: msgtime});
      });
    }
  ], (er, msg_dat) => {
    if (er) return cb(er);
    return cb(null, msg_dat);
  });
}

function _send_peer_msg(msg, receiver, cb) {
  async.waterfall([
    function(callback) {
      _get_frd_pubkey(receiver, (er, frdkey) => {
        if (er) return callback(er);
        return callback(null, Buffer.from(frdkey, encod).toString());
      });
    },
    function(frd_pubkey, callback) {
      _encrypt(Buffer.from(msg), frd_pubkey, (er, enc_msg) => {
        if (er) return callback(er);
        return callback(null, enc_msg);
      });
    },
    function(enc_msg, callback) {
      var d = new Date();
      var msgtime = `${d.getFullYear()}/${d.getMonth()}/${d.getDate()} ${d.getHours()}:${d.getMinutes()}`;
      _req({url: uri.msg, form: {rec: receiver, msg: enc_msg, time: msgtime}}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback(null, msgtime);
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(msgtime, callback) {
      db.get('name', (er, usern) => {
        if (er) return callback(er);
        return callback(null, {sen: usern, msg: msg, time: msgtime});
      });
    }
  ], (er, msg_dat) => {
    if (er) return cb(er);
    return cb(null, msg_dat);
  });
}

function send_msg(msg, receiver, cb) {
  if (receiver.includes('(G)')) {
    _send_group_msg(msg, receiver.split(' (G)')[0], (er, msg_dat) => {
      if (er) {
        return cb(er);
      }
      return cb(null, msg_dat);
    });
  } else {
    _send_peer_msg(msg, receiver, (er, msg_dat) => {
      if (er) {
        return cb(er);
      }
      return cb(null, msg_dat);
    });
  }
}

function _decrypt_group_msg(gname, sender, msg, cb) {
  async.waterfall([
    function(callback) {
      get_gmembers(gname, (er, members) => {
        if (er) {
          return callback(er);
        }
        if (members.indexOf(sender) === -1) {
          return callback(new Error(`'${sender}' is not a member of '${gname}'`));
        }
        return callback();
      });
    },
    function(callback) {
      _get_gkeys(gname, (er, keys) => {
        if (er) {
          return callback(er);
        }
        return callback(null, keys.priv);
      });
    },
    function(privkey, callback) {
      _decrypt(msg, privkey, (er, dec_msg) => {
        if (er) {
          return callback(er);
        }
        return callback(null, dec_msg);
      });
    }
  ], (er, dec_msg) => {
    if (er) return cb(er);
    return cb(null, dec_msg);
  });
}

function _decrypt_peer_msg(msg, cb) {
  async.waterfall([
    function(callback) {
      db.get('priv', (er, privkey) => {
        if (er) return callback(er);
        return callback(null, privkey);
      });
    },
    function(privkey, callback) {
      _decrypt(msg, privkey, (er, dec_msg) => {
        if (er) {
          return callback(er);
        }
        return callback(null, dec_msg);
      });
    }
  ], (er, dec_msg) => {
    if (er) return cb(er);
    return cb(null, dec_msg);
  });
}

function _decrypt_unread(unread_msgs, cb) {
  var msgs = [];
  async.each(unread_msgs, (unread, callback) => {
    if (unread.sen && unread.msg && unread.time) {
      if (unread.gname) {
        _decrypt_group_msg(unread.gname, unread.sen, Buffer.from(unread.msg).toString(), (er, decrypted_msg) => {
          if (er) {
            return callback(er);
          }
          msgs.push({sen: unread.sen, msg: decrypted_msg.toString(), time: unread.time, gname: unread.gname});
          return callback();
        });
      } else {
        _decrypt_peer_msg(Buffer.from(unread.msg).toString(), (er, decrypted_msg) => {
          if (er) {
            return callback(er);
          }
          msgs.push({sen: unread.sen, msg: decrypted_msg.toString(), time: unread.time});
          return callback();
        });
      }
    } else {
      return callback(new Error('invalid message token'));
    }
  }, (er) => {
    if (er) return cb(er);
    return cb(null, msgs);
  });
}

function fetch_unread(cb) {
  async.waterfall([
    function(callback) {
      _req({url: uri.unread}, (er, res) => {
        if (er) return callback(er);
        return callback(null, res);
      });
    },
    function(res, callback) {
      if (res && res.unread && res.unread.length > 0) {
        _decrypt_unread(res.unread, (er, msgs) => {
          if (er) return callback(er);
          return callback(null, msgs);
        });
      } else {
        return callback();
      }
    }
  ], (er, msgs) => {
    if (er) return cb(er);
    return cb(null, msgs);
  });
}

function is_reg_user(cb) {
  db.get('name', (er) => {
    if (er) return cb(false);
    return cb(true);
  });
}

function _check_gchat(gname, cb) {
  _req({url: uri.check_gchat, form: {gname: gname}}, (er, res) => {
    if (er) return cb(er);
    if (res.info && res.info === 'ok') {
      return cb();
    } else {
      return cb(new Error('no proper response received from the server'));
    }
  });
}

function _sign_gkey(gkey, cb) {
  async.waterfall([
    function(callback) {
      db.get('priv', (er, privkey) => {
        if (er) return callback(er);
        return callback(null, privkey);
      });
    },
    function(privkey, callback) {
      const sign = crypto.createSign('RSA-SHA256');
      sign.update(gkey);
      return callback(null, sign.sign(privkey, encod));
    }
  ], (er, sig) => {
    if (er) return cb(er);
    return cb(null, sig);
  });
}

function _verify_gkey(sender, key, sig, cb) {
  async.waterfall([
    function(callback) {
      _get_frd_pubkey(sender, (er, frd_pubkey) => {
        if (er) return callback(er);
        return callback(null, frd_pubkey);
      });
    },
    function(frd_pubkey, callback) {
      const veri = crypto.createVerify('RSA-SHA256');
      veri.update(key);
      if (!veri.verify(Buffer.from(frd_pubkey, encod).toString(), sig, encod)) {
        return callback(new Error('invalid group key signature'));
      } else {
        return callback();
      }
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function create_gchat(name, members, cb) {
  async.waterfall([
    function(callback) {
      _check_gchat(name, (er) => {
        if (er) return callback(er);
        return callback();
      });
    },
    function(callback) {
      var grsa = gen_rsakey();
      var grsa_concat = `${Buffer.from(grsa.private).toString(encod)}&${Buffer.from(grsa.public).toString(encod)}`;
      _sign_gkey(grsa_concat, (er, sig) => {
        if (er) return callback(er);
        return callback(null, grsa, grsa_concat, sig);
      });
    },
    function(grsa, grsa_concat, sig, callback) {
      db.get('name', (er, usern) => {
        if (er) return callback(er);
        var gmembers = members;
        gmembers.push(usern);
        _req({url: uri.create_gchat, form:{gname: name, gmembers: JSON.stringify(gmembers), gkey: grsa_concat, sig: sig}}, (er, res) => {
          if (er) return callback(er);
          if (res && res.info && res.info === 'ok') {
            return callback(null, grsa, usern.toString(), gmembers);
          } else {
            return callback(new Error('no proper response received from the server'));
          }
        });
      });
    },
    function(grsa, username, gmembers, callback) {
      db.get('groups', (er, groups) => {
        var grps;
        if (er) return callback(er);
        try {
          grps = JSON.parse(groups);
        } catch(er) {
          return callback(er);
        }
        grps.push({name: name, admin: username, privkey: grsa.private, pubkey: grsa.public, members: gmembers});
        db.put('groups', JSON.stringify(grps), (er) => {
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

function fetch_gchat_req(cb) {
  async.waterfall([
    function(callback) {
      _req({url: uri.fetch_gchat_req}, (er, res) => {
        if (er) return callback(er);
        return callback(null, res);
      });
    },
    function(res, callback) {
      if (res && res.gchat_req && res.gchat_req.admin && res.gchat_req.name && res.gchat_req.key && res.gchat_req.sig) {
        db.put('gchat_req', JSON.stringify(res.gchat_req), (er) => {
          if (er) return callback(er);
          return callback(null, {sender: res.gchat_req.admin, gname: res.gchat_req.name});
        });
      } else {
        return callback();
      }
    }
  ], (er, dat) => {
    if (er) return cb(er);
    return cb(null, dat);
  });
}

function _add_group(dat, cb) {
  db.get('groups', (er, groups) => {
    var grps;
    if (er) return cb(er);
    try {
      grps = JSON.parse(groups);
    } catch(er) {
      return cb(er);
    }
    var keys = dat.key.split('&'); // priv/pub keys are in base64
    grps.push({name: dat.name, admin: dat.admin, privkey: Buffer.from(keys[0], encod).toString(), pubkey: Buffer.from(keys[1], encod).toString(), members: dat.members});
    db.put('groups', JSON.stringify(grps), (er) => {
      if (er) return cb(er);
      return cb();
    });
  });
}

function verify_gchat_req(cb) {
  async.waterfall([
    function(callback) {
      db.get('gchat_req', (er, req) => {
        if (er) return callback(er);
        try {
          return callback(null, JSON.parse(req));
        } catch(er) {
          return callback(er);
        }
      });
    },
    function(req, callback) {
      _verify_gkey(req.admin, req.key, req.sig, (er) => {
        if (er) return callback(er);
        return callback(null, req);
      });
    },
    function(req, callback) {
      _add_group(req, (er) => {
        if (er) return callback(er);
        db.del('gchat_req', (er) => {
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

function send_gchat_rej(dat, cb) {    
  _req({url: uri.send_gchat_rej, form: {rec: dat.sender, gname: dat.name}}, (er, res) => {
    if (er) return cb(er);
    if (res.info && res.info === 'ok') {
      return cb();
    } else {
      return cb(new Error('no proper response received from the server'));
    }
  });
}

function fetch_gchat_rej(cb) { 
  async.waterfall([
    function(callback) {
      _req({url: uri.fetch_gchat_rej}, (er, res) => {
        if (er) return callback(er);
        if (res && res.gchat_rej && res.gchat_rej.rejector) {
          return callback(null, res.gchat_rej);
        } else {
          return callback(new Error('norej'));
        }
      });
    },
    function(gchat_rej, callback) {
      // remove member from group members
      var grps;
      db.get('groups', (er, groups) => {
        if (er) return callback(er);
        try {
          grps = JSON.parse(groups);
        } catch(er) {
          return callback(er);
        }
        grps.forEach((group) => {
          if (group.name === gchat_rej.gname) {
            group.members = group.members.splice(group.members.indexOf(gchat_rej.rejector), 1);
          }
        });
        return callback(null, gchat_rej, groups);
      });
    },
    function(gchat_rej, groups, callback) {
      db.put('groups', JSON.stringify(groups), (er) => {
        if (er) return callback(er);
        return callback(null, gchat_rej);
      });
    }
  ], (er, gchat_rej) => {
    if (er && er.message !== 'norej') return cb(er);
    return cb(null, gchat_rej);
  });
}

function is_group_admin(gname, cb) { 
  async.waterfall([
    function(callback) {
      db.get('name', (er, usern) => {
        if (er) return callback(er);
        return callback(null, usern);
      });
    },
    function(usern, callback) {
      db.get('groups', (er, groups) => {
        if (er) return callback(er);
        try {
          return callback(null, usern, JSON.parse(groups));
        } catch(er) {
          return callback(er);
        }
      });
    },
    function(usern, groups, callback) {
      var result = false;
      if (groups.length > 0) {
        groups.forEach((group) => {
          if (group.name === gname && group.admin === usern.toString()) {
            result = true;
          }
        });
      }
      return callback(null, result);
    }
  ], (er, result) => {
    if (er) return cb(er);
    return cb(null, result);
  });
}

function rm_group(gname, cb) {
  async.waterfall([
    function(callback) {
      get_gmembers(gname, (er, members) => {
        if (er) {
          return callback(er);
        }
        return callback(null, members);
      });
    },
    function(members, callback) {
      _req({url: uri.del_gchat, form:{gname: gname, gmembers: JSON.stringify(members)}}, (er, res) => {
        if (er) return callback(er);
        if (res && res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(callback) {
      db.get('groups', (er, groups) => {
        if (er) return callback(er);
        try {
          return callback(null, JSON.parse(groups));
        } catch(er) {
          return callback(er);
        }
      });
    },
    function(groups, callback) {
      var index = -1;
      if (groups.length > 0) {
        groups.forEach((group, i) => {
          if (group.name === gname) {
            index = i;
          }
        });
      }
      return callback(null, groups, index);
    },
    function(groups, index, callback) {
      if (index !== -1) {
        groups.splice(index, 1); // remove gname from groups
        db.put('groups', JSON.stringify(groups), (er) => {
          if (er) {
            return callback(er);
          }
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

function fetch_gchat_del(cb) {
  async.waterfall([
    function(callback) {
      _req({url: uri.fetch_gchat_del}, (er, res) => {
        if (er) return callback(er);
        if (res && res.gchat_del && res.gchat_del.gname && res.gchat_del.admin) {
          return callback(null, res.gchat_del);
        } else {
          return callback(new Error('nogchatdel'));
        }
      });
    },
    function(gchat_del, callback) {
      rm_group(gchat_del.gname, (er) => {
        if (er) {
          return callback(er);
        }
        return callback(null, gchat_del);
      });
    }
  ], (er, gchat_del) => {
    if (er && er.message !== 'nogchatdel') return cb(er);
    return cb(null, gchat_del);
  });
}

module.exports = {
  register: register,
  login: login,
  verify_frd_req: verify_frd_req,
  send_frd_req: send_frd_req,
  send_frd_rej: send_frd_rej,
  fetch_frd_req: fetch_frd_req,
  fetch_frd_rej: fetch_frd_rej,
  get_frds: get_frds,
  send_msg: send_msg,
  fetch_unread: fetch_unread,
  is_reg_user: is_reg_user,
  create_gchat: create_gchat,
  fetch_gchat_del: fetch_gchat_del,
  fetch_gchat_req: fetch_gchat_req,
  fetch_gchat_rej: fetch_gchat_rej,
  send_gchat_rej: send_gchat_rej,
  verify_gchat_req: verify_gchat_req,
  is_group_admin: is_group_admin,
  get_gmembers: get_gmembers,
  rm_group: rm_group
};
