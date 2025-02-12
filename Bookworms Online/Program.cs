using Bookworms_Online.Data;
using Bookworms_Online.Models;
using Bookworms_Online.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
var builder = WebApplication.CreateBuilder(args);

// Enable logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");
builder.Services.AddRazorPages();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddScoped<EncryptionService>();
builder.Services.AddScoped<AuditLogService>();
builder.Services.AddScoped<EmailService>();
builder.Services.AddScoped<PasswordHistoryService>();
builder.Services.AddScoped<ReCaptchaService>();
builder.Services.AddScoped<SessionTrackingService>();
builder.Services.AddHttpClient();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15); // Auto logout after 15 minutes of inactivity
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedEmail = false;
    options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider;

    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    options.Lockout.MaxFailedAccessAttempts = 3;


});
var app = builder.Build();


using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<ApplicationDbContext>();
    context.Database.Migrate();

    // Create admin user
    //await CreateAdminUser(services);
}

//async Task CreateAdminUser(IServiceProvider serviceProvider)
//{
//    var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
//    var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

//    string roleName = "Admin";
//    if (!await roleManager.RoleExistsAsync(roleName))
//    {
//        await roleManager.CreateAsync(new IdentityRole(roleName));
//    }

//    string adminEmail = "admin@bookwormsonline.com";
//    var adminUser = await userManager.FindByEmailAsync(adminEmail);
//    if (adminUser == null)
//    {
//        adminUser = new ApplicationUser { UserName = adminEmail, Email = adminEmail,BillingAddress="Block 230B Yishun",CreditCardNo="1234123412341234",FirstName="Admin",LastName="Admin",MobileNumber="12345678",ShippingAddress="Block 230B Yishun" ,PhotoPath="Null"};
//        await userManager.CreateAsync(adminUser, "SecurePassword123!");
//        await userManager.AddToRoleAsync(adminUser, roleName);
//    }
//}

var serviceProvider = builder.Services.BuildServiceProvider();
//await CreateAdminUser(serviceProvider);






if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error/ErrorPage");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<SessionTimeoutMiddleware>();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
