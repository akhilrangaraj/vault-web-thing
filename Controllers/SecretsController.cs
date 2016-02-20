using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Authorization;
using WebApplication.Models;
namespace WebApplication.Controllers
{
    [Authorize]
    public class SecretsController : Controller
    {
        public IActionResult Get([FromQuery]String vaultkey)
        {
            String urldecoded =  System.Net.WebUtility.UrlDecode(vaultkey);
            if (String.IsNullOrEmpty(urldecoded))
            {
                var json = new {Success=0, Error="No key was specified"};
                return Json(json);
            }
            return Json(new {Success=1});
        }
        [HttpGet]
        public IActionResult Set()
        {
            var json = new {Success=0, Error="You can't do this over post"};
            return Json(json);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Set(VaultRequest account)
        {
            var json = new {Success=0, Error="You can't do this over post"};
            return Json(json);
        }

    }
}
