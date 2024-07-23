import express, { Response, Request } from "express";

class HomeController {
  public path = "/";
  public router = express.Router();

  constructor() {
    this.initRoutes();
  }

  private initRoutes() {
    this.router.get("/", this.home);
  }

  home(req: Request, res: Response) {
    res.send("Welcome to the Homepage!");
  }
}

export default HomeController;