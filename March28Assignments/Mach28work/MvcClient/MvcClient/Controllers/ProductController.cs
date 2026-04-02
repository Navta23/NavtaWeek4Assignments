using Microsoft.AspNetCore.Mvc;
using MvcClient.Models;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace MVCProject.Controllers
{
    public class ProductController : Controller
    {
        private readonly IHttpClientFactory _factory;

        public ProductController(IHttpClientFactory factory)
        {
            _factory = factory;
        }


        public async Task<IActionResult> Index()
        {
            var client = _factory.CreateClient("api");

            var response = await client.GetAsync("Product?ts={DateTime.Now.Ticks}");

            if (!response.IsSuccessStatusCode)
                return Content("API call failed");

            var json = await response.Content.ReadAsStringAsync();

            var products = JsonSerializer.Deserialize<List<Product>>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            return View(products); // ✅ CORRECT
        }
    }
}