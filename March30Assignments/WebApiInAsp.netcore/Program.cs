using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApiInAsp.netcore.Models;

namespace WebApiInAsp.netcore
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddHttpContextAccessor();
           
            builder.Services.AddDbContext<EmpContext>
     (options => options.UseSqlServer(builder.Configuration.GetConnectionString("constring")));

            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<EmpContext>()
            .AddDefaultTokenProviders();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme =
                JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            });

            builder.Services.AddScoped<IEmployee, EmployeeService>(); //place it here only

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddControllersWithViews();
            builder.Services.AddEndpointsApiExplorer(); // Required for Swagger
            builder.Services.AddSwaggerGen();           // Adds Swagger support

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();  // ? Add this line
                app.UseSwagger();
                app.UseSwaggerUI();
            }
            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.

                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}
