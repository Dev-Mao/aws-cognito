import express, { Response, Request } from "express";
import { body, validationResult } from "express-validator";
import cognitoService from "../services/cognito.service";

class AuthController {
  public path = "/auth";
  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  private initRoutes() {
    this.router.post("/signUp", this.validateBody("signUp"), this.signUp);
    this.router.post("/signIn", this.validateBody("signIn"), this.signIn);
    this.router.post("/verify", this.validateBody("verify"), this.verify);
  }

  private signUp(req: Request, res: Response) {
    const result = validationResult(req);
    console.log(result);
    if (!result.isEmpty()) {
      return res.status(422).json({ errors: result.array() });
    }
    const cognito = new cognitoService();

    const { password, email} =
      req.body;

    cognito.signUpUser(email, password)
        .then(success => {
          success ? res.status(200).end() : res.status(400).end()
        })

    return res.status(200).end();
  }

  private signIn(req: Request, res: Response) {
    const result = validationResult(req);
    console.log(result);
    if (!result.isEmpty()) {
      return res.status(422).json({ errors: result.array() });
    }
    console.log("Sign in body is valid");
    return res.status(200).end();
  }

  private verify(req: Request, res: Response) {
    const result = validationResult(req);
    if (!result.isEmpty()) {
      return res.status(422).json({ errors: result.array() });
    }
    console.log("Verify body is valid");
    return res.status(200).end();
  }

  private validateBody(type: string) {
    switch (type) {
      case "signUp":
        return [
          body("email")
            .isEmail()
            .notEmpty()
            .withMessage("Please enter a valid email"),
          body("password")
            .isLength({ min: 8 })
            .withMessage("Password must be at least 8 characters long"),
          body("confirmPassword")
            .custom((value, { req }) => value === req.body.password)
            .withMessage("Passwords do not match"),
        ];
      case "signIn":
        return [
          body("email")
            .isEmail()
            .notEmpty()
            .withMessage("Please enter a valid email"),
          body("password").isLength({ min: 8 }),
        ];
      case "verify":
        return [
          body("email")
            .isEmail()
            .notEmpty()
            .withMessage("Please enter a valid email"),
          body("code").isLength({ min: 6, max: 6 }),
        ];
      default:
        return [];
    }
  }
}

export default AuthController;
