using System.ComponentModel.DataAnnotations;

namespace DoctorPatientAPI.DTOs.Requests
{
    public class UserToCreateModel
    {
        [Required(ErrorMessage = "Bad Request")]
        public string Login { get; set; }

        [Required(ErrorMessage = "Bad Request")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Bad Request")]
        public string Password { get; set; }

    }
}
