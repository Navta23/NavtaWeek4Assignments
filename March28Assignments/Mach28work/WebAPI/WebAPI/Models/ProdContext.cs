using Microsoft.EntityFrameworkCore;

namespace WebAPI.Models
{
    public class ProdContext : DbContext
    {
        public ProdContext(DbContextOptions<ProdContext> options)
            : base(options)
        {

        }
        public DbSet<Product> Products { get; set; }
    }
}
