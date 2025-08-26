using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureWebSite.Server.Data;
using SecureWebSite.Server.Models;

namespace SecureWebSite.Server.Controllers;

[ApiController]
[Route("api/securewebsite")]
public class SecureWebsiteController : ControllerBase
{
    private readonly SignInManager<User> _signInManager;
    private readonly UserManager<User> _userManager;
    private readonly ApplicationDbContext _db;

    public SecureWebsiteController(SignInManager<User> signInManager, UserManager<User> userManager, ApplicationDbContext db)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _db = db;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        if (dto == null || string.IsNullOrWhiteSpace(dto.Email) || string.IsNullOrWhiteSpace(dto.Password))
            return BadRequest(new { error = "Email and Password are required." });

        var existing = await _userManager.FindByEmailAsync(dto.Email);
        if (existing != null)
            return Conflict(new { error = "Email is already registered." });

        var user = new User
        {
            UserName = dto.Email,
            Email = dto.Email,
            Name = dto.Name ?? dto.Email,
            CreatedDate = DateTime.Now,
            ModifiedDate = DateTime.Now,
            LastLogin = DateTime.Now,
            IsAdmin = false
        };

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        return Ok(new { message = "Registered successfully." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Login model)
    {
        if (model == null || string.IsNullOrWhiteSpace(model.Password) || (string.IsNullOrWhiteSpace(model.Email) && string.IsNullOrWhiteSpace(model.Username)))
            return BadRequest(new { error = "Username/Email and Password are required." });

        User? user = null;
        if (!string.IsNullOrWhiteSpace(model.Email))
            user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null && !string.IsNullOrWhiteSpace(model.Username))
            user = await _userManager.FindByNameAsync(model.Username);

        if (user == null)
            return Unauthorized(new { error = "Invalid credentials." });

        var signInResult = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.Remember, lockoutOnFailure: false);

        if (!signInResult.Succeeded)
            return Unauthorized(new { error = "Invalid credentials." });

        user.LastLogin = DateTime.Now;
        await _userManager.UpdateAsync(user);

        return Ok(new { message = "Logged in successfully.", username = user.UserName, email = user.Email, isAdmin = user.IsAdmin });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok(new { message = "Logged out" });
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("admin-only")]
    public IActionResult AdminOnly() => Ok(new { message = "You are admin" });
}

public class RegisterDto
{
    public string Email { get; set; } = default!;
    public string Password { get; set; } = default!;
    public string? Name { get; set; }
}
