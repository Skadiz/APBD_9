using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.Models.DTOs.Response
{
    public class GetPrescriptionResponseDTO
    {
        public DateTime Date { get; set; }
        public DateTime DueDate { get; set; }
        public string Patient { get; set; }
        public string Doctor { get; set; }
        public IEnumerable<MedicamentInfoDTO> Medicaments { get; set; } = new HashSet<MedicamentInfoDTO>();
    }
}
