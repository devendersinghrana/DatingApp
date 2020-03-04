using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using DatingApp.API.Data.Interfaces;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userdto)
        {
            userdto.Username = userdto.Username.ToLower();
            if (await _repo.UserExists(userdto.Username))
                return BadRequest("Username already exists");

            var userToCreate = new User() { Username = userdto.Username };
            var createdUser = await _repo.Register(userToCreate, userdto.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userdto)
        {
            var userFromRepo = await _repo.Login(userdto.Username.ToLower(), userdto.Password);

            if (userFromRepo == null)
                return Unauthorized();

            //Payload: Id, UserName
            var claims = new[]{
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };

            //Crating a security key
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                        _config.GetSection("AppSettings:Token").Value));

            //Creating a signing credential 
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor(){
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new {token = tokenHandler.WriteToken(token)});
        }
    }
}