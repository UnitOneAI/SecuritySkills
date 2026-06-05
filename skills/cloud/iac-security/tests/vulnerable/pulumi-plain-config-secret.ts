import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const cfg = new pulumi.Config();
const dbPassword = cfg.require("dbPassword");
const apiToken = cfg.requireSecret("apiToken");

new aws.ssm.Parameter("db-password", {
  type: "SecureString",
  value: dbPassword,
});

apiToken.apply((token) => {
  console.log(`deploy token: ${token}`);
  return token;
});
