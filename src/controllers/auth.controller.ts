import express, { Response, Request } from "express";
import { body, validationResult } from "express-validator";
import CognitoService from "../services/cognito.service";

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

  private signUp = async (req: Request, res: Response) => {
    const result = validationResult(req);
    if (!result.isEmpty()) {
      return res.status(422).json({ errors: result.array() });
    }
    const { email, password } = req.body;
    const cognito = new CognitoService();

    try {
      const response = await cognito.signUpUser(email, password);
      if (response.success) {
        return res.status(201).json({ message: "Sign up successful", data: response.data });
      } else {
        return res.status(400).json({ message: "Sign up failed", error: response.error });
      }
    } catch (error) {
      return res.status(500).json({ message: "Internal server error", error });
    }
  };

  private signIn = async (req: Request, res: Response) => {
    const result = validationResult(req);
    if (!result.isEmpty()) {
      return res.status(422).json({ errors: result.array() });
    }
    const { email, password } = req.body;
    const cognito = new CognitoService();

    try {
      const response = await cognito.signInUser(email, password);
      if (response.success) {
        return res.status(200).json({ message: "Sign in successful", data: response.data });
      } else {
        return res.status(400).json({ message: "Sign in failed", error: response.error });
      }
    } catch (error) {
      return res.status(500).json({ message: "Internal server error", error });
    }
  };

  private verify = async (req: Request, res: Response) => {
    const result = validationResult(req);
    if (!result.isEmpty()) {
      return res.status(422).json({ errors: result.array() });
    }
    const { email, code } = req.body;
    const cognito = new CognitoService();

    try {
      const response = await cognito.verifyAccount(email, code);
      if (response.success) {
        return res.status(200).json({ message: "Account verification successful", data: response.data });
      } else {
        return res.status(400).json({ message: "Account verification failed", error: response.error });
      }
    } catch (error) {
      return res.status(500).json({ message: "Internal server error", error });
    }
  };

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
