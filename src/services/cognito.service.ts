import AWS from "aws-sdk";
import crypto from "crypto";

class cognitoService {
  private config = {
    region: "us-east-2",
  };
  private secretHash: string =
    "1r9s8jh9b094o4hgg28vie27mor86puc4t3olooi7l38po66bd68";
  private clientId: string = "1ivim9nngl630jrennbtsp7ba";

  private cognitoIdentity: AWS.CognitoIdentityServiceProvider;

  constructor() {
    this.cognitoIdentity = new AWS.CognitoIdentityServiceProvider(this.config);
  }

  public async signUpUser(username: string, password: string): Promise<boolean> {
    
    var params = {
      ClientId: this.clientId, 
      Password: password, 
      Username: username, 
      SecretHash: this.generateHash(username),
    }

    try {
      const data = await this.cognitoIdentity.signUp(params).promise()
      console.log(data)
      return true
    } catch (error) {
      console.log(error)
      return false
    }
  }

  private generateHash = (username: string): string => {
    return crypto
      .createHmac("sha256", this.secretHash)
      .update(username + this.clientId)
      .digest("base64");
  };
}

export default cognitoService;
