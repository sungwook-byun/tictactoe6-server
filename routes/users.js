var express = require('express');
var router = express.Router();
var bcrypt = require('bcrypt');
var saltRounds = 10;
const { ObjectId } = require('mongodb');

var ResponseType = {
  INVALID_USERNAME: 0,
  INVALID_PASSWORD: 1,
  SUCCESS: 2,
}

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

// 로그인
router.post('/signin', async function(req, res, next) {
  try {
    var username = req.body.username;
    var password = req.body.password;

    // 입력값 검증
    if (!username || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // DB 연결
    var database = req.app.get('database');
    var users = database.collection('users');

    // 사용자 조회
    const existingUser = await users.findOne({ username: username });
    if (existingUser) {
      var compareResult = bcrypt.compareSync(password, existingUser.password);
      if (compareResult) {
        // 세션에 사용자 정보 저장
        req.session.isAuthenticated = true;
        req.session.userId = existingUser._id.toString();
        req.session.username = existingUser.username;
        req.session.nickname = existingUser.nickname;
        res.json({ result: ResponseType.SUCCESS });
      } else {
        res.status(401).json({ result: ResponseType.INVALID_PASSWORD });
      }
    } else {
      res.status(401).json({ result: ResponseType.INVALID_USERNAME });
    }
  } catch (error) {
    console.error('Error during signin:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// 회원가입 (최종 버전)
router.post('/signup', async function(req, res, next) {
  try {
    var username = req.body.username;
    var password = req.body.password;
    var nickname = req.body.nickname;

    if (!username || !password || !nickname) {
      return res.json({ result: 2, message: 'All fields are required.' });
    }

    var database = req.app.get('database');
    var users = database.collection('users');

    var existingUser = await users.findOne({ username: username });
    if (existingUser) {
      return res.json({ result: 1, message: 'Username already exists.' });
    }

    var salt = bcrypt.genSaltSync(saltRounds);
    var hash = bcrypt.hashSync(password, salt);

    await users.insertOne({
      username: username,
      password: hash,
      nickname: nickname,
      createdAt: new Date()
    });

    return res.json({ result: 0, message: 'User registered successfully.' });
  } catch (error) {
    console.error('Error during signup:', error);
    return res.json({ result: 2, message: 'Internal server error.' });
  }
});


module.exports = router;