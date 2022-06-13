using Microsoft.AspNetCore.Authentication.JwtBearer;
using TestWebhookSendgrid.Auth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = AuthHelper.JwtDefaultValidationParameters(builder);
        options.Events = new JwtBearerEvents()
        {
            OnMessageReceived = context => AuthHelper.JwtMessageReceivedHandler(builder, context),
            OnTokenValidated = context => AuthHelper.JwtTokenValidationHandler(builder, context)
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{

    app.UseCors("DefaultPolicy");
}

app.MapControllers();

app.Run();
