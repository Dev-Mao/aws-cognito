import { 
  CognitoIdentityProviderClient, 
  SignUpCommand, 
  InitiateAuthCommand, 
  ConfirmSignUpCommand, 
  CognitoIdentityProviderServiceException,
  AuthFlowType,
  InitiateAuthCommandInput
} from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from "crypto";

class CognitoService {
  private config = {
    region: "us-east-2",
  };
  private secretHash: string =
    "1r9s8jh9b094o4hgg28vie27mor86puc4t3olooi7l38po66bd68";
  private clientId: string = "1ivim9nngl630jrennbtsp7ba";

  private cognitoIdentity: CognitoIdentityProviderClient;

  constructor() {
    this.cognitoIdentity = new CognitoIdentityProviderClient(this.config);
  }

  public async signUpUser(
    email: string,
    password: string
  ): Promise<{
    success: boolean;
    data?: any;
    error?: CognitoIdentityProviderServiceException;
  }> {
    const params = {
      ClientId: this.clientId,
      Password: password,
      Username: email,
      SecretHash: this.generateHash(email),
    };

    try {
      const command = new SignUpCommand(params);
      const data = await this.cognitoIdentity.send(command);
      console.log(data);
      return { success: true, data: data };
    } catch (error) {
      console.log(error);
      return {
        success: false,
        error: error as CognitoIdentityProviderServiceException,
      };
    }
  }

  public async signInUser(
    email: string, 
    password: string
  ): Promise<{ 
    success: boolean; 
    data?: any; 
    error?: CognitoIdentityProviderServiceException 
  }> {
    const params: InitiateAuthCommandInput = {
      AuthFlow: "USER_PASSWORD_AUTH" as AuthFlowType,
      ClientId: this.clientId,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
        SECRET_HASH: this.generateHash(email),
      },
    };

    try {
      const command = new InitiateAuthCommand(params);
      const data = await this.cognitoIdentity.send(command);
      return { success: true, data: data };
    } catch (error) {
      console.log(error);
      return { success: false, error: error as CognitoIdentityProviderServiceException };
    }
  }

  public async verifyAccount(
    email: string,
    code: string
  ): Promise<{
    success: boolean;
    data?: any;
    error?: CognitoIdentityProviderServiceException;
  }> {
    const params = {
      ClientId: this.clientId,
      ConfirmationCode: code,
      Username: email,
      SecretHash: this.generateHash(email),
    };

    try {
      const command = new ConfirmSignUpCommand(params);
      const data = await this.cognitoIdentity.send(command);
      console.log(data);
      return { success: true, data: data };
    } catch (error) {
      console.log(error);
      return {
        success: false,
        error: error as CognitoIdentityProviderServiceException,
      };
    }
  }

  private generateHash = (username: string): string => {
    return createHmac("sha256", this.secretHash)
      .update(username + this.clientId)
      .digest("base64");
  };
}

export default CognitoService;
