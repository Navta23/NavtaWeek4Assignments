using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using WebApiInAsp.netcore.Models;
using static System.Net.Mime.MediaTypeNames;

namespace WebApiInAsp.netcore
{
    public class EmployeeService : IEmployee
    {
        private readonly EmpContext _context;
        private readonly IWebHostEnvironment _env;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public EmployeeService(EmpContext context, IWebHostEnvironment env,
            IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _env = env;
            _httpContextAccessor = httpContextAccessor;
        }

        public string GetBaseUrl()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null) throw new InvalidOperationException("No HttpContext");
            var request = httpContext.Request;
            return $"{request.Scheme}://{request.Host}";

        }
        public async Task<Employee> AddEmployeeAsync(Employee employee, IFormFile? image)
        {
            if (image != null && image.Length > 0)
            {
                employee.ImagePath = SaveImageToUploads(image);
            }
            else
            {
                employee.ImagePath = "/uploads/default.jpg";
            }
            await _context.Employees.AddAsync(employee);
            await _context.SaveChangesAsync();
            employee.ImagePath = GetBaseUrl() + employee.ImagePath;
            return employee;
        }

        public async Task<Employee?> DeleteEmployeeAsync(int id)
        {
            var employee = await _context.Employees.FindAsync(id);
            if(employee == null)
            {
                return null;
            }
            DeleteImageFile(employee.ImagePath);
            _context.Employees.Remove(employee);
            await _context.SaveChangesAsync();
            employee.ImagePath = null;
            return employee;
        }

        public async Task<List<Employee>> GetAllEmployeesAsync(int pageNumber, int pageSize)
        {
            var employees = await _context.Employees.
                 Skip((pageNumber - 1) * pageSize).Take(pageSize).ToListAsync();
            string baseUrl = GetBaseUrl();
            foreach(var e in employees)
            {
                e.ImagePath = string.IsNullOrEmpty(e.ImagePath)
                    ? baseUrl + "/uploads/default.jpeg" : baseUrl + e.ImagePath;
            }
            return employees;
        }

        //I want to add search functionality also means i want to filter the data 
        public async Task<List<EmployeeBasicDto>> GetAllEmployeeBasicInfoAsync
            (int pageNumber, int pageSize, string? searchterm)
        {
            var query = _context.Employees.AsQueryable();
            if (!string.IsNullOrEmpty(searchterm))
            {
                query = query.Where(e => e.FirstName!.Contains(searchterm) ||
                            e.LastName!.Contains(searchterm) ||
                            e.Email!.Contains(searchterm));
            }
            var employees = await query
                    .Skip((pageNumber-1) * pageSize)
                    .Take(pageSize)
                    .ToListAsync();
            string baseUrl = GetBaseUrl();
            var basicList = employees.Select(e => new EmployeeBasicDto
            {
                Id = e.Id,
                FirstName = e.FirstName,
                LastName = e.LastName,
                Email = e.Email,
                ImageUrl = string.IsNullOrEmpty(e.ImagePath)
                            ? baseUrl + "/uploads/default.jpeg"
                            : baseUrl + e.ImagePath,
            }).ToList();
            return basicList;
        }
        public async Task<Employee?> GetEmployeeByIdAsync(int id)
        {
            var emp = await _context.Employees.FindAsync(id);
            if(emp != null)
            {
                emp.ImagePath = string.IsNullOrEmpty(emp.ImagePath)
             ? GetBaseUrl() + "/uploads/default.jpeg"
             : GetBaseUrl() + emp.ImagePath;
            }
            return emp;
        }

        private void DeleteImageFile(string? imagePath)
        {
            if (string.IsNullOrEmpty(imagePath) || imagePath.Contains("default.jpeg"))
                return;

            var fullPath = Path.Combine
                (_env.WebRootPath, imagePath.TrimStart('/').Replace
                ('/', Path.DirectorySeparatorChar));
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
            }
        }

        private string SaveImageToUploads(IFormFile image)
        {
            var imageName = Guid.NewGuid().ToString() + Path.GetExtension(image.FileName);
            var uploadPath = Path.Combine(_env.WebRootPath, "uploads");

            if (!Directory.Exists(uploadPath))
                Directory.CreateDirectory(uploadPath);

            var fullPath = Path.Combine(uploadPath, imageName);
            using var stream = new FileStream(fullPath, FileMode.Create);
            image.CopyTo(stream);

            return "/uploads/" + imageName;
        }
        public async Task<Employee?> UpdateEmployeeAsync(Employee employee, IFormFile? image) // ? -> you can either update the image or not  your will
        {
            var existing = await _context.Employees.FindAsync(employee.Id);
            if (existing == null) return null;

            existing.FirstName = employee.FirstName;
            existing.LastName = employee.LastName;
            existing.Email = employee.Email;
            existing.Age = employee.Age;

            if (image != null && image.Length > 0)
            {
                DeleteImageFile(existing.ImagePath);
                existing.ImagePath = SaveImageToUploads(image);
            }


            await _context.SaveChangesAsync();
            if (!string.IsNullOrEmpty(existing.ImagePath))
                existing.ImagePath = GetBaseUrl() + existing.ImagePath;

            return existing;
        }

        
    }
}
