using Microsoft.AspNetCore.Mvc;
using WebApiInAsp.netcore.Models;

namespace WebApiInAsp.netcore
{
    public interface IEmployee
    {
        Task<List<Employee>> GetAllEmployeesAsync(int pageNumber, int pageSize);
        Task<List<EmployeeBasicDto>> GetAllEmployeeBasicInfoAsync(int pageNumber, int pageSize, string searchterm);
        Task<Employee?> GetEmployeeByIdAsync(int id);
        Task<Employee> AddEmployeeAsync(Employee employee, IFormFile image);
        Task<Employee?> UpdateEmployeeAsync(Employee employee, IFormFile? image);
        Task<Employee?> DeleteEmployeeAsync(int id);

    }
}
