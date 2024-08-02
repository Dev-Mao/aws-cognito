import express, { Response, Request } from "express";
import AuthMiddleware from "../middlewares/auth.middleware";

class ProtectedController {
  public path = "/protected";
  public router = express.Router();
  public authMiddleware: AuthMiddleware;

  constructor() {
    this.authMiddleware = new AuthMiddleware();
    this.initRoutes();
  }

  private initRoutes() {
    this.router.use(this.authMiddleware.verifyToken);
    this.router.get("/secret", this.secret);
  }

  secret = (req: Request, res: Response) => {
    res.send("you can view secret");
  };
}

export default ProtectedController;
