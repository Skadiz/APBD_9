using DoctorPatientAPI.Models;
using DoctorPatientAPI.Models.DTOs.Request;
using DoctorPatientAPI.Models.DTOs.Response;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.Services
{
    public interface IDoctorDbService 
    {
        public Task<IEnumerable<GetDoctorInfoDTO>> GetDoctors(MainDbContext context);
        public Task PostDoctor(MainDbContext context, CreateDoctorRequestDTO doctorInput);
        public Task PutDoctor(MainDbContext context, CreateDoctorRequestDTO doctorInput, string index);
        public Task DeleteDoctor(MainDbContext context, string index);
    }

    public class DoctorDbService : IDoctorDbService
    {
        public async Task<IEnumerable<GetDoctorInfoDTO>> GetDoctors(MainDbContext context)
        {
            var doctors = await context.Doctors.Include(e => e.Prescriptions).ThenInclude(e => e.IdPatientNavigation)
                                         .Select(e => new GetDoctorInfoDTO
                                         {
                                             FirstName = e.FirstName,
                                             LastName = e.LastName,
                                             Email = e.Email,
                                             Patients = e.Prescriptions.Select(x => new PatientInfoDTO
                                             {
                                                 FirstName = x.IdPatientNavigation.FirstName,
                                                 LastName = x.IdPatientNavigation.LastName
                                             })
                                         })
                                         .ToListAsync();
            return doctors;
        }

        public async Task PostDoctor(MainDbContext context, CreateDoctorRequestDTO doctorInput)
        {
            var doctor = new Doctor
            {
                IdDoctor = context.Doctors.Max(e => e.IdDoctor) + 1,
                FirstName = doctorInput.FirstName,
                LastName = doctorInput.LastName,
                Email = doctorInput.Email
            };
            context.Doctors.Add(doctor);
            await context.SaveChangesAsync();
        }

        public async Task PutDoctor(MainDbContext context, CreateDoctorRequestDTO doctorInput, string index)
        {
            if (!await DoctorExists(int.Parse(index)))
            {
                throw new ArgumentException("Doctor with ID " + index + " doesnt exists");
            }
            var doctor = new Doctor
            {
                IdDoctor = int.Parse(index),
                FirstName = doctorInput.FirstName,
                LastName = doctorInput.LastName,
                Email = doctorInput.Email
            };
            context.Doctors.Attach(doctor);
            context.Entry(doctor).State = EntityState.Modified;
            await context.SaveChangesAsync();
        }

        public async Task DeleteDoctor(MainDbContext context, string index)
        {
            if (!await DoctorExists(int.Parse(index)))
            {
                throw new ArgumentException("Doctor with ID " + index + " doesnt exists");
            }

            var doctor = new Doctor
            {
                IdDoctor = int.Parse(index)
            };
            var prescriptions = await GetPrescriptionsWithIdDoctor(int.Parse(index));

            foreach (var p in prescriptions)
            {
                var pres_med = await GetPrescriptions_MedicamentWithIdPrescription(p.IdPrescription);
                context.Prescriptions.Remove(p);
                context.Prescription_Medicaments.Remove(pres_med);
            }
            context.Doctors.Attach(doctor);
            context.Entry(doctor).State = EntityState.Deleted;
            await context.SaveChangesAsync();
        }

        private async Task<bool> DoctorExists(int idDoctor)
        {
            var context = new MainDbContext();
            var result = await context.Doctors
                .Where(t => t.IdDoctor == idDoctor)
                .ToListAsync();

            return result.Count > 0;
        }

        private async Task<IEnumerable<Prescription>> GetPrescriptionsWithIdDoctor(int doctorIndex)
        {
            var context = new MainDbContext();
            var prescriptions = await context.Prescriptions
                                             .Where(e => e.IdDoctor == doctorIndex)
                                             .ToListAsync();
            return prescriptions;
        }
        private async Task<Prescription_Medicament> GetPrescriptions_MedicamentWithIdPrescription(int prescriptionIndex)
        {
            var context = new MainDbContext();
            var prescription_medicament = await context.Prescription_Medicaments
                                             .Where(e => e.IdPrescription == prescriptionIndex)
                                             .FirstAsync();
            return prescription_medicament;
        }
    }
}
