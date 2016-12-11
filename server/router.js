'use strict';
const express = require('express');
const router = express.Router();
const auth = require('./auth.js');

router.post('/init_reg', (req, res, next) => {
  auth.init_register(req.body.usern, (er) => {  
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/reg', (req, res, next) => {
  auth.register(req.body.usern, req.body.pub, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/init_login', (req, res, next) => {
  auth.init_login(req.body.usern, (er, challenge) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({challenge: challenge});
    }
  });
});

router.post('/login', (req, res, next) => {
  auth.login(req.body.usern, req.body.challenge_back, (er, tok) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({token: tok});
    }
  });
});

router.post('/send_frd_req', (req, res, next) => {
  auth.send_frd_req(req.decod.sub, req.body.rec, req.body.pubtag, (er) => { 
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/fetch_frd_req', (req, res, next) => {
  auth.fetch_frd_req(req.decod.sub, (er, req) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({frd_req: req});
    }
  });
});

router.post('/fetch_frd_rej', (req, res, next) => {
  auth.fetch_frd_rej(req.decod.sub, (er, rej) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({frd_rej: rej});
    }
  });
});

router.post('/send_frd_rej', (req, res, next) => {
  auth.send_frd_rej(req.decod.sub, req.body.rec, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/msg', (req, res, next) => {
  var dat = {
    rec: req.body.rec,
    msg: req.body.msg,
    time: req.body.time
  };
  auth.handle_msg(req.decod.sub, dat, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/g_msg', (req, res, next) => {
  var dat;
  try {  
    dat = {
      name: req.body.gname,
      msg: req.body.msg,
      members: JSON.parse(req.body.gmembers),
      time: req.body.time
    };
  } catch(er) {
    res.json({err: er.message});
  }
  auth.handle_group_msg(req.decod.sub, dat, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/unread', (req, res, next) => {
  auth.fetch_unread(req.decod.sub, (er, unread) => {
    if (er) {
      res.json({err: er.message});
    } else {
      auth.clear_unread(req.decod.sub, (er) => {
        if (er) {
          res.json({err: er.message});
        } else {
          res.json({unread: unread});
        }
      });
    }
  });
});

router.post('/check_gchat', (req, res, next) => {
  auth.check_gchat(req.body.gname, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/create_gchat', (req, res, next) => {
  var dat;
  try {  
    dat = {
      name: req.body.gname,
      key: req.body.gkey,
      members: JSON.parse(req.body.gmembers),
      sig: req.body.sig
    };
  } catch(er) {
    res.json({err: er.message});
  }
  auth.create_gchat(req.decod.sub, dat, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/del_gchat', (req, res, next) => {
  var dat;
  try {  
    dat = {
      name: req.body.gname,
      members: JSON.parse(req.body.gmembers)
    };
  } catch(er) {
    res.json({err: er.message});
  }
  auth.del_gchat(req.decod.sub, dat.name, dat.members, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

router.post('/fetch_gchat_del', (req, res, next) => {
  auth.fetch_gchat_del(req.decod.sub, (er, del) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({gchat_del: del});
    }
  });
});

router.post('/fetch_gchat_req', (req, res, next) => {
  auth.fetch_gchat_req(req.decod.sub, (er, req) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({gchat_req: req});
    }
  });
});

router.post('/fetch_gchat_rej', (req, res, next) => {
  auth.fetch_gchat_rej(req.decod.sub, (er, rej) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({gchat_rej: rej});
    }
  });
});

router.post('/send_gchat_rej', (req, res, next) => {
  auth.send_gchat_rej(req.decod.sub, req.body.dat, (er) => {
    if (er) {
      res.json({err: er.message});
    } else {
      res.json({info: 'ok'});
    }
  });
});

module.exports = router;