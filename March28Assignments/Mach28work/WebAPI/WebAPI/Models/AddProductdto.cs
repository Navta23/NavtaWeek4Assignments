using System.ComponentModel.DataAnnotations;

namespace WebAPI.Models
{
    public class AddProductdto
    {
        [Required(ErrorMessage = "Please enter product name")]
        public string? Name { get; set; }

        [Required(ErrorMessage = "Please enter product price")]
        [Range(0.01, 10000, ErrorMessage = "Price must be between 0.01 and 10000")]
        public decimal Price { get; set; }

        [Required(ErrorMessage = "Please enter product category")]
        public string? Category { get; set; }
    }
}
