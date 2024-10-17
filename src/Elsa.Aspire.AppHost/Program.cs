using Aspire.Hosting;

var builder = DistributedApplication.CreateBuilder(args);
var adminUsername = builder.AddParameter("adminUsername", secret: true);
var adminPassword = builder.AddParameter("adminPassword", secret: true);

var keycloak = builder.AddKeycloak("keycloak", 8080, adminUsername: adminUsername, adminPassword: adminPassword)
    .WithDataVolume()
    .WithImageTag("25.0")
    .WithArgs("--features", "organization");

var postgresdb = builder.AddPostgres("pg")
    .WithDataVolume()
    .AddDatabase("elsadb");

//var sqlserverdb = builder.AddSqlServer("sqlserver",adminPassword)
//    .WithDataVolume()
//    .AddDatabase("elsadb");

var messaging = builder.AddRabbitMQ("messaging");

var server = builder.AddProject<Projects.ElsaServer>("elsaserver")
        .WithReference(keycloak)
        .WithReference(postgresdb)
        .WithReference(messaging);

builder.AddProject<Projects.ElsaStudioServer>("elsastudio")
    .WithReference(keycloak)
    .WithReference(server);

builder.Build().Run();
