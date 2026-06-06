const grpc = require("@grpc/grpc-js");
const protoLoader = require("@grpc/proto-loader");

const packageDefinition = protoLoader.loadSync("admin.proto");
const adminProto = grpc.loadPackageDefinition(packageDefinition).admin;

const users = new Map();

function deleteUser(call, callback) {
  users.delete(call.request.userId);
  callback(null, { deleted: true });
}

const server = new grpc.Server();
server.addService(adminProto.AdminService.service, { deleteUser });
server.bindAsync("0.0.0.0:50051", grpc.ServerCredentials.createInsecure(), () => {
  server.start();
});
