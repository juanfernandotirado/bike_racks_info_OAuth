const fetch = require('node-fetch');

exports.auth = (req, res, next)=>{

  let jwks

  fetch('https://www.googleapis.com/oauth2/v3/certs')
  .then(response =>{
    return response.json();
  })
  .then(data =>{
    jwks = data
    console.log('*** JWKS: ',jwks);    
  })
  .then(result =>{
    let token = (req.headers.authorization != undefined ? req.headers.authorization.split(' ')[1] : '')

    if(!token){
      console.log('*** Error')
      res.send('*** Error: No Token ****')  
    }
  
    try{
    var jwt = require('jsonwebtoken');
    var jwkToPem = require('jwk-to-pem');
  
    // First need to find out which key id is being used, we can get this from the header
    var d = jwt.decode(token,{complete:true});
    
    // Need to convert the key to PEM format
    var pem;
    if (d.header.kid) {  
      jwks.keys.forEach( k => {
        if (k.kid == d.header.kid)
          pem = jwkToPem(k);
      });
    }
    console.log(pem);
  
    // We use the PEM cert to verify the token is signed by google
    // Basically, we try to decrypt the 3rd part of the token using the public key
    var result = jwt.verify(token, pem);
    
    // jwt.verify will return the body of the token
    console.log(result);
    
    console.log('auth');
    
    next();
    
    }catch(err){
      res.status(401).send('No valid Token')
    }
  })
}
