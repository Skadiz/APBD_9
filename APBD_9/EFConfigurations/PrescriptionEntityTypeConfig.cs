using DoctorPatientAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.EFConfigurations
{
    public class PrescriptionEntityTypeConfig : IEntityTypeConfiguration<Prescription>
    {
        public void Configure(EntityTypeBuilder<Prescription> builder)
        {
            builder.HasKey(e => e.IdPrescription);

            builder.Property(e => e.IdPrescription).ValueGeneratedNever();

            builder.Property(e => e.Date).IsRequired().HasColumnType("datetime");

            builder.Property(e => e.DueDate).IsRequired().HasColumnType("datetime");

            builder.HasOne(d => d.IdDoctorNavigation)
                   .WithMany(p => p.Prescriptions)
                   .HasForeignKey(d => d.IdDoctor)
                   .OnDelete(DeleteBehavior.ClientSetNull);

            builder.HasOne(d => d.IdPatientNavigation)
                   .WithMany(p => p.Prescriptions)
                   .HasForeignKey(d => d.IdPatient)
                   .OnDelete(DeleteBehavior.ClientSetNull);

            // seed data
            builder.HasData(
                    new Prescription { IdPrescription = 1, Date = DateTime.Now, DueDate = DateTime.Now, IdPatient = 2, IdDoctor = 2 },
                    new Prescription { IdPrescription = 2, Date = DateTime.Now, DueDate = DateTime.Now, IdPatient = 3, IdDoctor = 1 },
                    new Prescription { IdPrescription = 3, Date = DateTime.Now, DueDate = DateTime.Now, IdPatient = 1, IdDoctor = 3 },
                    new Prescription { IdPrescription = 4, Date = DateTime.Now, DueDate = DateTime.Now, IdPatient = 3, IdDoctor = 2 },
                    new Prescription { IdPrescription = 5, Date = DateTime.Now, DueDate = DateTime.Now, IdPatient = 1, IdDoctor = 1 }
                );
        }
    }
}
