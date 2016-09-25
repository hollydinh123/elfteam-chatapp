#!/usr/bin/env node
'use strict';

const path = require('path');
const crypto = require('crypto');
const levelup = require('levelup');
const read = require('read');
const readline = require('readline');
const io = require('socket.io-client');
const jwt = require('jsonwebtoken');
const col = require('chalk');
const encoding = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const arg = process.argv[2];
const sock = io.connect('https://localhost.daplie.com:3761/live/auth');

/**
 * create an elliptic curve Diffie-Hellman key exchange for this
 * private chat session and generate the client dh public key 
 * to send to the other client
 */

const client_dh = crypto.createECDH('secp256k1');
const clientkey = client_dh.generateKeys(encoding);

var db = levelup(path.resolve('..', 'db'));

function er(error) {
  console.error(`\nerror: ${error}`);
}

function log(info) {
  console.log(`\n${info}`);
}

function exit(code) {
  sock.disconnect();
  process.exit(code);
}

function gen_sign(data, cb) {
  var sign;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message, null);
    }
    sign = crypto.createSign('RSA-SHA256');
    sign.write(data);
    sign.end();
    return cb(null, sign.sign(privkey, encoding));
  });
}

function get_frds(cb) {
  var frds;
  db.get('frd', (err, val) => {
    if (err) {
      return cb(err.message);
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message);
    }
    if (frds.ls.length > 0) {
      return cb(null, frds.ls);
    } else {
      return cb();
    }
  });
}

function get_frd_pubkey(frd_username, cb) {
  var frd_pubkey;
  get_frds((err, frds) => {
    if (err) {
      return cb(err, null);
    }
    frds.forEach((frd) => {
      if (frd.pubkey && frd.name === frd_username) {
        frd_pubkey = Buffer.from(frd.pubkey, encoding).toString();
      }
    });
    return cb(null, frd_pubkey);
  });
}

function encrypt(msg, receiver, cb) {
  var hmac_key, iv, hmac, tag, key_encrypted, cipher, cipher_text;

  get_frd_pubkey(receiver, (err, rec_pubkey) => {
    if (err) {
      return cb(err, null);
    }
    if (rec_pubkey) {
      db.get('dh_sec', (err, dh_sec) => {
        if (err) {
          return cb(err.message);
        }
        try {
          hmac_key = crypto.randomBytes(32);
          iv = crypto.randomBytes(16); // initialization vector 128 bits
          hmac = crypto.createHmac(hmac_alg, hmac_key);

          // encrypt the message with dh secret and random iv
          cipher = crypto.createCipheriv(alg, Buffer.from(dh_sec, encoding), iv);
          cipher_text = cipher.update(msg, 'utf8', encoding);
          cipher_text += cipher.final(encoding);

          hmac.update(cipher_text);
          hmac.update(iv.toString(encoding));
          tag = hmac.digest(encoding);

          // encrypt the hmac key with receiver's public key
          key_encrypted = crypto.publicEncrypt(rec_pubkey, Buffer.from(hmac_key));

          // concatenate key, cipher text, iv and hmac digest
          return cb(null, `${key_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`);
        } catch(err) {
          return cb(err.message, null);
        } 

      });
    } else {
      return cb('friend\'s public key not found');
    }
  });
}

function decrypt(cipher_text, cb) {
  var chunk, key_encrypted, ct, iv, tag,hmac_key, 
    hmac, computed_tag, decipher, decrypted;

  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message, null);
    }
    db.get('dh_sec', (err, dh_sec) => {
      if (err) {
        return cb(err.message);
      }
      try {
        chunk = cipher_text.split('#');
        key_encrypted = Buffer.from(chunk[0], encoding);
        ct = chunk[1];
        iv = Buffer.from(chunk[2], encoding);
        tag = chunk[3];
        hmac_key = crypto.privateDecrypt(privkey, key_encrypted);

        hmac = crypto.createHmac(hmac_alg, Buffer.from(hmac_key));
        hmac.update(ct);
        hmac.update(iv.toString(encoding));
        computed_tag = hmac.digest(encoding);
        if (computed_tag !== tag) {
          return cb('integrity tag not valid');
        }
        decipher = crypto.createDecipheriv(alg, Buffer.from(dh_sec, encoding), iv);
        decrypted = decipher.update(ct, encoding, 'utf8');
        decrypted += decipher.final('utf8');
        return cb(null, decrypted);
      } catch(err) {
        return cb(err.message, null);
      }
    });
  });
}

function logout(cb) {  
  db.get('tok', (err, tok) => {
    if (err) {
      er(err.message);
      return cb(err.message);
    }
    sock.emit('logout', {token: tok}).on('logout-err', (err) => {
      er(err);
      return cb(err);
    }).on('logout-success', (dat) => {
      db.batch().del('tok').del('session_dat').write(() => {
        log(dat);
        return cb();
      });
    });  
  });
}

function login(usern, passw, cb) {
  const login_sock = io.connect('https://localhost.daplie.com:3761/live/login');
  gen_sign(passw, (err, sig) => {  
    if (err) {
      login_sock.disconnect();
      return cb(err);
    }
    login_sock.emit('login', {un: usern, pw: passw, pw_sig: sig}).on('login-err', (err) => {  
      login_sock.disconnect();
      return cb(err);
    }).on('login-success', (dat) => {  
      if (dat.token) {
        db.put('tok', dat.token, (err) => {
          if (err) {    
            login_sock.disconnect();
            return cb(err.message);
          } else {    
            log('logged in successfully');
            login_sock.disconnect();
            return cb();
          }
        });
      } else {  
        er('server-err: no authorization token');
        login_sock.disconnect();
        return cb('server-err: no authorization token');
      }
    });
  });
}

function gen_jwt(dat, cb) {
  var tok;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message);
    }
    dat = Object.assign(dat, {iat: new Date().getTime(), exp: Math.floor(new Date().getTime()/1000) + 60*60});
    // sign jwt asymmetric with RSA SHA256
    tok = jwt.sign(dat, privkey, {algorithm: 'RS256'});
    return cb(null, tok);
  });
}

function verify_tok(token, frd, cb) {
  get_frd_pubkey(frd, (err, frd_pubkey) => {
    if (err) {
      return cb(err);
    }
    // verify jwt asymmetric
    jwt.verify(token, frd_pubkey, {algorithms: 'RS256'}, (err, decod) => {
      if (err) {
        return cb(err.message);
      } else {
        return cb(null, decod);
      }
    });
  });
}

process.on('SIGINT', () => {
  logout((err) => {
    if (err) {
      er(err);
      exit(1);
    }
    exit(0);
  });
});

if (arg === 'login') {
  console.log();
  read({prompt: 'username: '}, (err, usern) => {
    if (err) {
      er(err);
      exit(1);
    }
    read({prompt: 'password: ', silent: true}, (err, passw) => {
      if (err) {
        er(err);
        exit(1);
      }
      login(usern, passw, (err) => {
        if (err) {
          er(err);
          exit(1);
        } else {
          exit(0);
        }
      });
    });
  });
} else if (arg === 'ls') {
  get_frds((err, frds) => {
    var ls = [];
    if (err) {
      er(err);
      exit(1);
    }
    if (frds.length > 0) {
      frds.forEach((frd) => {
        if (ls.indexOf(frd.name) === -1) {
          ls.push(frd.name);
        }
      });
      console.log(ls);
      exit(0);
    } else {
      log('no friend found');
      exit(0);
    }
  });
} else if (arg !== 'login' && arg !== undefined && arg !== '') {
  db.get('name', (err, username) => {
    if (err) {
      er(err.message);
      sock.disconnect();
      exit(1);
    }
    db.get('tok', (err, tok) => {
      if (err) {
        er(err);
        sock.disconnect();
        exit(1);
      }
      sock.emit('authenticate', {token: tok}).on('authenticated', () => {  
        var rl = readline.createInterface({input: process.stdin, output: process.stdout});
        log(col.italic(`a private chat request sent to ${col.magenta(arg)}, waiting for a response..`));

        // send a private chat request to a friend
        sock.emit('req-chat', {sender: username, receiver: arg}).on('req-chat-reject', (dat) => {  
          log(`${col.magenta(dat.receiver)} rejected the offer`);
          logout((err) => {
            if (err) {
              er(err);
              exit(1);
            }
            exit(0);
          });
        }).on('priv-chat-accepted', (dat) => {  
          var dh_sec;
          verify_tok(dat.token, dat.receiver, (err, decod) => {
            if (err) {
              er(err);
              exit(1);
            }
            if (decod && decod.dh) {
              dh_sec = client_dh.computeSecret(decod.dh, encoding, encoding);
              db.put('dh_sec', dh_sec, (err) => {
                if (err) {
                  er(err.message);
                  exit(1);
                }
                gen_jwt({dh: clientkey}, (err, tok) => {
                  if (err) {
                    er(err);
                    exit(1);
                  }
                  dat = Object.assign(dat, {token: tok});
                  sock.emit('priv-chat-sender-key', dat);
                });
              });
            } else {
              er('token not valid');
              exit(1);
            }
          });
        }).on('priv-chat-ready', (dat) => {  
          db.put('session_dat', JSON.stringify(dat), (err) => {
            if (err) {
              er(err.message);
              exit(1);
            } else {
              log(col.italic.green(`${dat.sender} and ${dat.receiver} are ready to have a private conversation`));
              rl.setPrompt(col.gray(`${dat.sender}: `));
              rl.prompt();
            }
          });
        }).on('priv-msg-res', (dat) => {
          // verify token and decrypt the message
          verify_tok(dat.token, dat.sender, (err, decod) => {
            if (err) {
              er(err);
              exit(1);
            }
            if (decod && decod.msg) {
              decrypt(decod.msg, (err, decrypted) => {
                if (err) {
                  er(err);
                  exit(1);
                }
                log(`${col.magenta(dat.sender)}: ${decrypted}`);
                rl.prompt();
              });
            } else {
              er('token not valid');
              exit(1);
            }
          }); 
        });

        rl.on('line', (msg) => {
          var dat;
          db.get('session_dat', (err, session_dat) => {
            if (err) {
              er(err);
              exit(1);
            }
            try {
              dat = JSON.parse(session_dat);
            } catch(err) {
              er(err);
              exit(1);
            }
            // encrypt the message and sign the message token
            encrypt(msg, dat.receiver, (err, enc_dat) => {
              if (err) {
                er(err);
                exit(1);
              }
              gen_jwt({msg: enc_dat}, (err, tok) => {
                if (err) {
                  er(err);
                  exit(1);
                }
                sock.emit('priv-msg', {room: dat.room, sender: dat.sender, token: tok});
                rl.prompt();
              });
            });
          });
        }).on('close', () => {
          logout((err) => {
            if (err) {
              er(err);
              exit(1);
            }
            exit(0);
          });
        });
      }).on('unauthorized', (msg) => {
        er(`socket unauthorized: ${JSON.stringify(msg.data)}`);
        er(msg.data.type);
        exit(1);
      });
    }); 
  });
} else {
  db.get('tok', (err, tok) => {
    if (err) {
      er(err);
      exit(1);
    }
    sock.emit('authenticate', {token: tok}).on('authenticated', () => {
      var rl = readline.createInterface({input: process.stdin, output: process.stdout});
      log(col.italic('Your friends private chat requests will be shown up here..'));

      // receive a private chat request from a friend  
      sock.on('req-priv-chat', (dat) => {
        rl.question(col.italic.cyan(`\n${col.magenta(dat.sender)} wants to have a private conversation. Do you accept? [y/n] `), (ans) => {
          if (ans.match(/^y(es)?$/i)) {  
            gen_jwt({dh: clientkey}, (err, tok) => {
              if (err) {
                er(err);
                exit(1);
              }
              dat = Object.assign(dat, {token: tok});
              sock.emit('req-priv-chat-accept', dat);
            });
          } else {
            sock.emit('req-priv-chat-reject', dat);
            log(col.italic(`a reject response sent to ${col.magenta(dat.sender)}`));
          }
        });
      }).on('priv-chat-sender-pubkey', (dat) => {  
        var dh_sec;
        verify_tok(dat.token, dat.sender, (err, decod) => {
          if (err) {
            er(err);
            exit(1);
          }
          if (decod && decod.dh) {
            dh_sec = client_dh.computeSecret(decod.dh, encoding, encoding);
            db.put('dh_sec', dh_sec, (err) => {
              if (err) {
                er(err);
                exit(1);
              }
              sock.emit('priv-chat-key-exchanged', {
                room: dat.room,
                sender: dat.sender,
                receiver: dat.receiver
              });
            });
          } else {
            er('token not valid');
            exit(1);
          }
        });
      }).on('priv-chat-ready', (dat) => {  
        db.put('session_dat', JSON.stringify(dat), (err) => {
          if (err) {  
            er(err.message);
            rl.close();
            exit(1);
          } else {
            log(col.italic.green(`${dat.sender} and ${dat.receiver} are ready to have a private conversation`));
            rl.setPrompt(col.gray(`${dat.receiver}: `));
            rl.prompt();
          }
        });
      }).on('priv-msg', (dat) => {
        // verify token and decrypt the message
        verify_tok(dat.token, dat.sender, (err, decod) => {
          if (err) {
            er(err);
            exit(1);
          }
          if (decod && decod.msg) {
            decrypt(decod.msg, (err, decrypted) => {
              if (err) {
                er(err);
                exit(1);
              }
              log(`${col.magenta(dat.sender)}: ${decrypted}`);
              rl.prompt();
            });
          } else {
            er('token not valid');
            exit(1);
          }
        });
      });

      rl.on('line', (msg) => {  
        var dat;
        db.get('session_dat', (err, session_dat) => {
          if (err) {
            er(err.message);
            rl.close();
            exit(1);
          }
          try {
            dat = JSON.parse(session_dat);
          } catch(err) {
            er(err);
            exit(1);
          }
          // encrypt and sign the message token
          encrypt(msg, dat.sender, (err, enc_dat) => {
            if (err) {
              er(err);
              exit(1);
            }
            gen_jwt({msg: enc_dat}, (err, tok) => {
              if (err) {
                er(err);
                exit(1);
              }
              sock.emit('priv-msg-res', {room: dat.room, sender: dat.receiver, token: tok});
              rl.prompt();
            });
          });
        });
      }).on('close', () => {
        logout((err) => {
          if (err) {
            er(err);
            exit(1);
          }
          exit(0);
        });
      }).on('unauthorized', (msg) => {
        er(`socket unauthorized: ${JSON.stringify(msg.data)}`);
        er(msg.data.type);
        exit(1);
      });
    });
  });
}
