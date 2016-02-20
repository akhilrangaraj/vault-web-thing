using System.ComponentModel.DataAnnotations;

namespace WebApplication.Models
{
    public class VaultRequest
    {
        [Required]
        public string Path { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Value { get; set; }

    }
}
