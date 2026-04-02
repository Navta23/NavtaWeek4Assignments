using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebAPI.Models;
using static System.Net.Mime.MediaTypeNames;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductController : ControllerBase
    {
        private readonly IProduct _productService;
        public ProductController(IProduct productService)
        {
            _productService = productService;
        }
        [HttpGet]
        public async Task<ActionResult<List<Product>>> GetAll(int page=1, int pageSize=5)
        {
            return Ok(await _productService.GetAllProductAsync(page, pageSize));
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Product>> GetById(int id)
        {
            var product = await _productService.GetProductByIdAsync(id);
            if(product == null)
            {
                return NotFound("Prodct not found");
            }
            return Ok(product);
        }

        [HttpPost]
        public async Task<ActionResult<List<Product>>> Add([FromForm]Product prod)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var added = await _productService.AddProductAsync(prod);
            return Ok(added);
        }

        [HttpPut("{id}")]
        public async Task<ActionResult<List<Product>>> Update(int id, [FromForm]Product prod)
        {
            if (id != prod.Id)
            {
                return BadRequest("Id mismatched!!");
            }
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var product = await _productService.UpdateProductAsync(prod);
            if (product == null)
                return BadRequest("Employee not found");
            return Ok(product);
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult<List<Product>>> Delete(int id)
        {
            var deleted = await _productService.DeleteProductAsync(id);
            if (deleted == null)
                return NotFound("Employee not found to delete");
            return Ok(deleted);
        }
    }
}
