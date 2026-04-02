using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebApiInAsp.netcore.Controllers
{
    public class EmployeeUIController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        public IActionResult Create()
        {
            return View();
        }
        public IActionResult Details()
        {
            return View();
        }
        
        public ActionResult Edit(int id)
        {
            ViewBag.Id = id;
            return View();
        }

        public ActionResult Delete(int id)
        {
            ViewBag.Id = id;
            return View();
        }

        public IActionResult Export()
        {
            return View();
        }

    }
}
