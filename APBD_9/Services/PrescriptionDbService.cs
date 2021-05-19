using DoctorPatientAPI.Models;
using DoctorPatientAPI.Models.DTOs.Response;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.Services
{

    public interface IPrescriptionDbservise
    {
        public Task<GetPrescriptionResponseDTO> GetPrescription(MainDbContext context, string index);
    }

    public class PrescriptionDbService : IPrescriptionDbservise
    {
        public async Task<GetPrescriptionResponseDTO> GetPrescription(MainDbContext context, string index)
        {
            int idPrescription = int.Parse(index);
            var prescription = await context.Prescriptions
                                            .Where(e => e.IdPrescription == int.Parse(index))
                                            .Include(e => e.IdDoctorNavigation)
                                            .Include(e => e.IdPatientNavigation)
                                            .Include(e => e.PrescriptionMedicaments).ThenInclude(e => e.IdMedicamentNavigation)
                                            .Select(e => new GetPrescriptionResponseDTO
                                            {
                                                Date = e.Date,
                                                DueDate = e.DueDate,
                                                Patient = e.IdPatientNavigation.FirstName + " " + e.IdPatientNavigation.LastName,
                                                Doctor = e.IdDoctorNavigation.FirstName + " " + e.IdDoctorNavigation.LastName,
                                                Medicaments = e.PrescriptionMedicaments.Select(e => new MedicamentInfoDTO
                                                {
                                                    Name = e.IdMedicamentNavigation.Name,
                                                    Description = e.IdMedicamentNavigation.Description,
                                                    Type = e.IdMedicamentNavigation.Type
                                                })
                                            })
                                            .FirstOrDefaultAsync();
            return prescription;
        }
    }
}
