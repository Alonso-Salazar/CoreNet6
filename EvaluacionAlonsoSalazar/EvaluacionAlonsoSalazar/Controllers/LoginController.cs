using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using EvaluacionAlonsoSalazar.Helpers;
using System.Data;
using System.Security.Claims;
using EvaluacionAlonsoSalazar.Models;


namespace EvaluacionAlonsoSalazar.Controllers
{
    public class LoginController : Controller
    {
        private readonly AdventureWorks2019Context _context;
        private readonly ILogger<LoginController> _logger;

        public LoginController(AdventureWorks2019Context context, ILogger<LoginController> logger)
        {
            _context = context;
            _logger = logger;
        }
        
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string Email, string Password)
        {
            var userInfo = await (from P in _context.People
                                  join Em in _context.EmailAddresses on P.BusinessEntityId equals Em.BusinessEntityId
                                  join Pass in _context.Passwords on P.BusinessEntityId equals Pass.BusinessEntityId
                                  where Em.EmailAddress1 == Email
                                  select new
                                  {
                                      IDEmployee = P.BusinessEntityId,
                                      Nombre = P.FirstName,
                                      Apellido = P.LastName,
                                      Email = Em.EmailAddress1,
                                      Password = Pass.PasswordHash,
                                      Permisos_Id = P.Permisos.Select(x => x.PermisoId),
                                      Permisos_Desc = P.Permisos.Select(x => x.PermisoNombre)
                                  }).SingleOrDefaultAsync();

            if (userInfo != null)
            {
                if (Argon2PasswordHasher.VerifyHashedPassword(userInfo.Password, Password))
                {

                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, userInfo.IDEmployee.ToString()),
                        new Claim(ClaimTypes.NameIdentifier, userInfo.IDEmployee.ToString()),
                        new Claim(ClaimTypes.GivenName, userInfo.Nombre.ToString()),
                        new Claim(ClaimTypes.Surname, userInfo.Apellido.ToString()),
                        new Claim(ClaimTypes.Email, userInfo.Email.ToString()),
                    };

                    var allPermisos = userInfo.Permisos_Id;

                    foreach (var permiso in allPermisos)
                    {
                        claims.Add(new Claim("Permiso", permiso.ToString()));
                    }

                    var claimsIdentity = new ClaimsIdentity(claims, "CookieAuth");
                    await HttpContext.SignInAsync(
                        "CookieAuth",
                        new ClaimsPrincipal(claimsIdentity));

                    return RedirectToAction("Index", "Home");
                }
                TempData["ErrorMessage"] = "Email o Contraseña Incorrectos";
                return RedirectToAction("Index", "Login");
            }
            TempData["ErrorMessage"] = "Email o Contraseña Incorrectos";
            return RedirectToAction("Index", "Login");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync("CookieAuth");
            return RedirectToAction("Index", "Login");
        }


    }
}

