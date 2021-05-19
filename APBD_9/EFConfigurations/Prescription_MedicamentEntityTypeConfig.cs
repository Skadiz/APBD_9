using DoctorPatientAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.EFConfigurations
{
    public class Prescription_MedicamentEntityTypeConfig : IEntityTypeConfiguration<Prescription_Medicament>
    {
        public void Configure(EntityTypeBuilder<Prescription_Medicament> builder)
        {
            builder.HasKey(e => e.IdMedicament);
            builder.HasKey(e => e.IdPrescription);

            builder.Property(e => e.Dose);

            builder.Property(e => e.Details).IsRequired()
                                            .HasMaxLength(100);

            builder.HasOne(d => d.IdPrescriptionNavigation)
                   .WithMany(p => p.PrescriptionMedicaments)
                   .HasForeignKey(d => d.IdPrescription)
                   .OnDelete(DeleteBehavior.ClientSetNull);

            builder.HasOne(d => d.IdMedicamentNavigation)
                   .WithMany(p => p.PrescriptionMedicaments)
                   .HasForeignKey(d => d.IdMedicament)
                   .OnDelete(DeleteBehavior.ClientSetNull);

            // seed data
            builder.HasData(
                    new Prescription_Medicament { IdMedicament = 1, IdPrescription = 1, Dose = 3, Details = "default" },
                    new Prescription_Medicament { IdMedicament = 2, IdPrescription = 2, Dose = null, Details = "default" },
                    new Prescription_Medicament { IdMedicament = 3, IdPrescription = 3, Dose = 10, Details = "default" },
                    new Prescription_Medicament { IdMedicament = 4, IdPrescription = 4, Dose = null, Details = "default" },
                    new Prescription_Medicament { IdMedicament = 5, IdPrescription = 5, Dose = 5, Details = "default" }
                );
        }
    }
}
