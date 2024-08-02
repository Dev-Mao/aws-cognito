import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";

let pems: any = {};
class AuthMiddleware {
  private poolRegion: string = "us-east-2";
  private poolId: string = "us-east-2_BGqb12Xil";

  constructor() {
    this.setUp();
  }

  verifyToken(req: Request, res: Response, next) {
    const token = req.header("Auth");
    console.log(token);
    if (!token) {
      return res.status(401).end();
    }
    let decodeJWT: any = jwt.decode(token, { complete: true });
    if (!decodeJWT) {
      return res.status(401).end();
    }
    let kid = decodeJWT.header.kid;
    let pem: string = pems[kid];
    if (!pem) {
      return res.status(401).end();
    }

    jwt.verify(token, pem, (err, payload) => {
      if (err) {
        console.log(err);
        return res.status(401).end();
      }
      console.log(payload);
      next();
    });
  }

  private async setUp() {
    const URL = `https://cognito-idp.${this.poolRegion}.amazonaws.com/${this.poolId}/.well-known/jwks.json`;

    try {
      const response = await fetch(URL);
      if (response.status !== 200) {
        throw "request no successful";
      }
      const data: any = await response.json();
      const { keys } = data;
      for (let index = 0; index < keys.length; index++) {
        const key = keys[index];
        const key_id = key.kid;
        const modulus = key.n;
        const exponent = key.e;
        const key_type = key.kty;
        const jwk = { kty: key_type, n: modulus, e: exponent };
        const pem = jwkToPem(jwk);
        pems[key_id] = pem;
      }
      console.log("got all pems");
    } catch (error) {
      console.log(error);
      console.log("Error! Unable to download JWKs");
    }
  }
}

export default AuthMiddleware;
