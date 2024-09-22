
using Microsoft.AspNetCore.Mvc;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Dapper;
using System.Transactions;
using System.Data;
using AdidataDbContext.Models.Mysql.PTPDev;
using NPOI.SS.Formula.Functions;
using NPOI.POIFS.Crypt.Dsig;
using Org.BouncyCastle.Asn1.Cms;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace BasicProject.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly PTPDevContext ptpDevContext;

        public AuthenticationController(IConfiguration configuration, PTPDevContext ptpDevContext)
        {
            this.configuration = configuration;
            this.ptpDevContext = ptpDevContext;
            responseObject = new ResponseObject();
            responseMessage = new ResponseMessage();
        }

        public ResponseObject responseObject { get; set; }
        public ResponseMessage responseMessage { get; set; }


        [HttpPost]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            try
            {
                var user = await ptpDevContext.Users.FirstOrDefaultAsync();

                if (user.Email == login.Email && user.Password == login.Password)
                {
                    var findToken = await ptpDevContext.UsersTokens.FirstOrDefaultAsync(x => x.Nama == user.Name);

                   /* var token = Guid.NewGuid().ToString();*/
                    var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                    var hostname = Dns.GetHostName();

                    var claims = new[] {
                        new Claim(JwtRegisteredClaimNames.Sub, configuration["Jwt:Subject"]),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim("UserId", user.Id.ToString()),
                        new Claim("Email", user.Email.ToString()),
                    };

                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
                    var signin = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                    var token = new JwtSecurityToken(
                            configuration["Jwt:Issuer"],
                            configuration["Jwt:Audience"],
                            claims,
                            expires: DateTime.UtcNow.AddMinutes(60),
                            signingCredentials: signin
                        );
                    string tokenValue = new JwtSecurityTokenHandler().WriteToken(token);

                    var userToken = new UsersToken
                    {
                        UserId = user.Id,
                        Nama = user.Name,
                        Token = tokenValue,
                        IpAddress = ipAddress,
                        Hostname = hostname,
                        CreatedTime = DateTime.Now,
                        ExpiredTime = DateTime.Now.AddHours(2),
                    };

                    if (findToken == null)
                    {
                        ptpDevContext.UsersTokens.Add(userToken);
                        await ptpDevContext.SaveChangesAsync();
                    }
                    else
                    {
                        findToken.Token = tokenValue;
                        await ptpDevContext.SaveChangesAsync();
                    }

                    SetResponseObject(200, "Berhasil Login", userToken);
                    return Ok(responseObject);

                }
                else if(user.Email != login.Email)
                {
                    SetResponseMessage(401, "Email yang anda masukan salah!");
                    return Ok(responseMessage);
                }
                else
                {
                    SetResponseMessage(401, "Password yang anda masukan salah!");
                    return Ok(responseMessage);
                }

            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Internal Error " + ex.Message);
            }

        }


        [HttpDelete]
        public async Task<IActionResult> Logout([FromQuery] int id)
        {
            try
            {
                var userToken = await ptpDevContext.UsersTokens.FirstOrDefaultAsync(x=>x.UserId == id);
                ptpDevContext.UsersTokens.Remove(userToken);
                await ptpDevContext.SaveChangesAsync();
                SetResponseMessage(200, "Berhasil Logout");
                return Ok(responseMessage);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Internal Error " + ex.Message);
            }
        }


        [Authorize]
        [DisableCors]
        [HttpGet]
        public async Task<IActionResult> GetUser()
        {
            try
            {
                var users = User.FindFirst("UserId")?.Value;
                int userId = int.Parse(users);
                var user = await ptpDevContext.Users.FindAsync(userId);


                var data = await ptpDevContext.Users.ToListAsync();

                SetResponseObject(200, "Success", user);

                return Ok(responseObject);
            }
            catch(Exception ex) {
                return StatusCode(StatusCodes.Status500InternalServerError , "Internal Error " + ex.Message);
            
            }
        }


        private void SetResponseObject(int status, string message, object data)
        {
            responseObject.Status = status;
            responseObject.Message = message;
            responseObject.Data = data;
        }


        private void SetResponseMessage(int status, string message)
        {
            responseMessage.Status = status;
            responseMessage.Message = message;
        }
        

    }
}


