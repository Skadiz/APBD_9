using DoctorPatientAPI.DTOs.Requests;
using DoctorPatientAPI.Models;
using DoctorPatientAPI.Services;
using DoctorPatientAPI.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


namespace DoctorPatientAPI.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly MainDbContext _dbContext;

        public AccountsController(IConfiguration configuration, MainDbContext context)
        {
            _configuration = configuration;
            _dbContext = context;
        }


        [AllowAnonymous]
        [HttpPost("register")]
        public IActionResult AddSUser(UserToCreateModel newUserToRequest)
        {
            var hashedPasswordAndSalt = SecurityHelpers.GetHashedPasswordAndSalt(newUserToRequest.Password);
            string password = "alaMaKota";

            var context = new MainDbContext();
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");

            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            string saltBase64 = Convert.ToBase64String(salt);

            var user = new User()
            {
                Login = newUserToRequest.Login,
                Email = newUserToRequest.Email,
                Password = hashedPasswordAndSalt.Item1,
                Salt = hashedPasswordAndSalt.Item2,
                RefreshToken = null,
                RefreshTokenExp = null
            };

            context.Table_Users.Add(user);
            context.SaveChanges();

            return Ok("New user was added");
        }


        [AllowAnonymous]
        [HttpPost("login")]
        public IActionResult Login(LoginRequest loginRequest)
        {
            var context = new MainDbContext();
            User user = context.Table_Users.Where(u => u.Login == loginRequest.Login).FirstOrDefault();

            string passwordHash = user.Password;

            //Validating password
            //#####

            // generate a 128-bit salt using a secure PRNG
            byte[] salt = Convert.FromBase64String(user.Salt);

            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            //Password based key derivation function
            string currentHashedPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: loginRequest.Password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));
            //#####

            //Here we check the hash
            if (passwordHash != currentHashedPassword)
            {
                return Unauthorized();
            }

            Claim[] userclaim = new[] {
                    new Claim(ClaimTypes.Name, "s19240"),
                    new Claim(ClaimTypes.Role, "user"),
                    new Claim(ClaimTypes.Role, "admin")
                    //Add additional data here
                };

            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecretKey"]));

            SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: "http://localhost:55280",
                audience: "http://localhost:55280",
                claims: userclaim,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: creds
            );

            user.RefreshToken = GenerateRefreshToken();
            user.RefreshTokenExp = DateTime.Now.AddDays(1);
            context.SaveChanges();

            return Ok(new
            {
                accessToken = new JwtSecurityTokenHandler().WriteToken(token),
                refreshToken = user.RefreshToken
            });
        }


        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken(int userId, string refresh_token)
        {
            var user = _dbContext.Table_Users.Where(u => u.IdUser == userId).FirstOrDefault();
            if (user == null)
            {
                throw new SecurityTokenException("Invalid refresh token");
            }

            if (user.RefreshTokenExp < DateTime.Now)
            {
                throw new SecurityTokenException("Refresh token expired");
            }


            if (user.RefreshToken == refresh_token)
            {
                Claim[] userclaim = new[] {
                    new Claim(ClaimTypes.Name, "s19240"),
                    new Claim(ClaimTypes.Role, "user"),
                    new Claim(ClaimTypes.Role, "admin")
                    //Add additional data here
                };

                SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecretKey"]));

                SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                JwtSecurityToken token = new JwtSecurityToken(
                    issuer: "http://localhost:55280",
                    audience: "http://localhost:55280",
                    claims: userclaim,
                    expires: DateTime.Now.AddMinutes(10),
                    signingCredentials: creds
                );

                user.RefreshToken = GenerateRefreshToken();
                user.RefreshTokenExp = DateTime.Now.AddDays(1);
                _dbContext.SaveChanges();

                return Ok(new
                {
                    accessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    refreshToken = user.RefreshToken
                });
            }

            return Unauthorized();
        }


        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}

