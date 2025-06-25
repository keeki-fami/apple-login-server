const http = require("http");
const jwt = require("jsonwebtoken"); //??
const appleSignin = require("apple-signin-auth");
require('dotenv').config();

const SECRET_KEY = process.env.Jwt_Secret;
const APPLE_CLIENT_ID = process.env.Apple_Client_Id;

http.createServer((req,res)=>{
  if(req.method==="POST" && req.url==="/appleSignIn"){
    let body = "";
    
    //postされたデータを受け取る
    req.on("data",chunk=>{
        body += chunk;
    });

    req.on("end",async ()=>{
	try{
          const {identityToken, nonce} = JSON.parse(body);
          
	  //Appleトークンの検証
	  const payload = await appleSignin.verifyIdToken(identityToken,{
	    audience:APPLE_CLIENT_ID,
	    nonce: nonce,
	  });

	  //JWTトークンの生成
	  const token = jwt.sign(
	    {
	      sub:payload.sub,
	      email:payload.email,
	    },
	    SECRET_KEY,
	    {expiresIn: "1h"}
	  );

          res.writeHead(200,{
	    "Content-Type":"text/plain;charset=utf-8"
	  });
	  res.write(`Apple ID sub:${payload.sub}\n`);
	  res.end(JSON.stringify({token}));
	}catch(e){
	  res.writeHead(400,{
            "Content-Type":"text/plain;charset=utf-8"
          });	
	  res.end("invalid request");
	}
    });
  }else{
    res.writeHead(404,{
        "Content-Type":"text/plain;charset=utf-8"
    });
  }

}).listen(PORT,()=>{
  console.log('Server running on port ${PORT}');
});
