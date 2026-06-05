import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const cfg = new pulumi.Config();
const dbPassword = cfg.requireSecret("dbPassword");

new aws.rds.Instance("db", {
  allocatedStorage: 20,
  engine: "postgres",
  instanceClass: "db.t4g.micro",
  username: "app",
  password: dbPassword,
});
