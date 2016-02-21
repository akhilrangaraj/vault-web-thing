using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNet.Authorization;
using WebApplication.Models;
using Turbocharged.Vault;

namespace WebApplication.Controllers
{
    [Authorize]
    public class SecretsController : Controller
    {
        private readonly IConfigurationRoot Configuration;
        private VaultClient _vaultClient;
        public SecretsController()
        {
                var builder = new ConfigurationBuilder();
                builder.AddJsonFile("appsettings.json");
                builder.AddUserSecrets();
                Configuration = builder.Build();
                //TODO: get logged in user, and connect using user's token if created
                var authentication = new TokenAuthentication(Configuration["Vault:Root:VaultAuthToken"]);
                var vaultAddr = new System.Uri(Configuration["Vault:VaultAddress"]);
                _vaultClient = new VaultClient(vaultAddr, authentication);
        }
        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }
        [HttpGet]
        public async Task<IActionResult> Get([FromQuery]String vaultkey)
        {
            String urldecoded = System.Net.WebUtility.UrlDecode(vaultkey);
            if (String.IsNullOrEmpty(urldecoded))
            {
                var json = new { Success = 0, Error = "No key was specified" };
                return Json(json);
            }
            try
            {
                var vaultPath = "secret/" + urldecoded;
                var lease = await _vaultClient.LeaseAsync(vaultPath);
                if (lease == null)
                {
                    var json = new { Success = 0, Error = "Key was not found" };
                    return Json(json);
                }
                else {
                    var json = new { Success = 1, Data = Json(lease.Data["Value"]) };
                    return Json(json);
                }
            }
            catch (Exception e)
            {
                var json = new { Success = 0, Error = e.ToString() };
                return Json(json);
            }
        }
        [HttpGet]
        public IActionResult Set()
        {
            var json = new {Success=0, Error="You can't do this over Get"};
            return Json(json);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Set(VaultRequest account)
        {
            var json = new {Success=0, Error="Unknown Error"};
            return Json(json);
        }

    }
}