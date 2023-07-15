const express=require('express');
const router=express.Router();
const passport=require('passport');
const LocalStrtagey=require('passport-local');
const crypto=require('crypto');
const db=require('../db');

// configure the Local password strategy
passport.use(new LocalStrtagey((username, password, cb)=>{

    db.get('SELECT * FROM users WHERE username=?', [username],function(err,row){
      if(err) {
        return cb(err);
      }

      if(!row){
        return cb(null, false, {
          message:'Incorrect name or password.'
        })
      }

      crypto.pbkdf2(password, row.salt, 31000, 32, 'sha256', (err,hashedPassword)=>{
        if(err){
          return cb(err);
        }
        if(!crypto.timingSafeEqual(row.hashed_password, hashedPassword)){
          return cb(null, false, {
            messae:"Incorrect username or password"
          })
        }
        return cb(null, row)
      })
    })
}))

// persist user infofrmation
passport.serializeUser((user,cb)=>{
  process.nextTick(()=>{
    cb(null, {
      id:user.id, username:user.username
    })
  })
})

// deserialize the user
passport.deserializeUser((user,cb)=>{
  process.nextTick(()=>{
    return cb(null, user);
  })
})



router.get('/login', function(req,res){
  res.render('login')
});
router.post('/login/password',  (req,res)=>{
  res.send('/', {csrfToken:req.csrfToken()})
})

router.post('/logout', (req,res,next)=>{
  req.logout((err)=>{
    if(err) return next(err);
    res.redirect('/')
  })
})
module.exports=router