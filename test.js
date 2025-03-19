const crypto = require('./index.js')
;(async () => {
  try {
    await crypto.initialize('69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc')
    console.log(crypto.randomBytes())
    let keys = crypto.generateKeypair()
    console.log(keys)
    let testObj = { test: 'test' }
    console.log(crypto.hashObj(testObj))
    crypto.signObj(testObj, keys.secretKey, keys.publicKey)
    console.log(testObj)
    console.log(crypto.verifyObj(testObj))
  } catch (e) {
    console.log(e)
  }
})()
