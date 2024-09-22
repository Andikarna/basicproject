using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerUI;
using System.Text;
using Newtonsoft.Json.Serialization;
using AdidataDbContext.Models.Mysql.PTPDev;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using PTP.ViewModel;
using System.Text.Json;

namespace BasicProject
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddControllers();

            services.AddDbContext <PTPDevContext>(options =>
                options.UseMySql(Configuration.GetConnectionString("PTP"),
                Microsoft.EntityFrameworkCore.ServerVersion.Parse("10.4.28-mariadb")));

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Recruitment API Services", Version = "v1" });

                var securitySchema = new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "bearer",
                    BearerFormat = "JWT",

                    Reference = new OpenApiReference
                    {
                        Id = JwtBearerDefaults.AuthenticationScheme,
                        Type = ReferenceType.SecurityScheme
                    }
                };
                c.AddSecurityDefinition("Bearer", securitySchema);

                var security = new OpenApiSecurityRequirement();
                security.Add(securitySchema, new[] { "Bearer" });
                c.AddSecurityRequirement(security);

            });

            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll",
                    builder =>
                    builder.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader());
            });

            services.AddSession(option =>
            {
                option.IdleTimeout = TimeSpan.FromMinutes(15);

            });

            services.AddControllersWithViews()
               .AddNewtonsoftJson(options =>
               options.SerializerSettings.ReferenceLoopHandling = Newtonsoft
               .Json.ReferenceLoopHandling.Ignore)
               .AddNewtonsoftJson(options => options.SerializerSettings.ContractResolver
               = new CamelCasePropertyNamesContractResolver());


            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
           .AddJwtBearer(options =>
           {
               options.TokenValidationParameters = new TokenValidationParameters
               {
                   ValidateIssuer = true,
                   ValidateAudience = true,
                   ValidateLifetime = true,
                   ValidateIssuerSigningKey = true,
                   ValidIssuer = Configuration["Jwt:Issuer"],
                   ValidAudience = Configuration["Jwt:Audience"],
                   IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"])),
                 
               };
               options.Events = new JwtBearerEvents
               {
                   OnChallenge = context =>
                   {
                       // Menghapus response default agar tidak override pesan kita
                       context.HandleResponse();

                       // Set status code dan custom message
                       context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                       context.Response.ContentType = "application/json";
                       var result = JsonSerializer.Serialize(new { message = "Unautorizhe Token" });

                       return context.Response.WriteAsync(result);
                   }
               };

           });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
            services.AddHttpContextAccessor();
      
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseCors(options => options.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/ptpdev/swagger/v1/swagger.json", "Dokumen");
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Dokumen");
                c.DocumentTitle = "Documentation";
                c.DocExpansion(DocExpansion.List);
            });

            app.UseRouting();
            app.UseCors("AllowAll");
            app.UseSession();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}