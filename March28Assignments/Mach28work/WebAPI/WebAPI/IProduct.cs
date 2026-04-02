using WebAPI.Models;
namespace WebAPI
{
    public interface IProduct
    {
        Task<List<Product>> GetAllProductAsync(int pageNumber, int pageSize);
        Task<Product?> GetProductByIdAsync(int id);
        Task<Product> AddProductAsync(Product product);
        Task<Product?> UpdateProductAsync(Product employee);
        Task<Product?> DeleteProductAsync(int id);
    }
}
