using DoctorPatientAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.EFConfigurations
{
    public class MedicamentEntityTypeConfig : IEntityTypeConfiguration<Medicament>
    {
        public void Configure(EntityTypeBuilder<Medicament> builder)
        {
            builder.HasKey(e => e.IdMedicament);

            builder.Property(e => e.IdMedicament).ValueGeneratedNever();

            builder.Property(e => e.Name).IsRequired()
                                         .HasMaxLength(200);

            builder.Property(e => e.Description).IsRequired()
                                                .HasMaxLength(500);

            builder.Property(e => e.Type).IsRequired()
                                         .HasMaxLength(100);

            // seed data
            builder.HasData(
                    new Medicament { IdMedicament = 1, Name = "", Description = "default", Type = "" },
                    new Medicament { IdMedicament = 2, Name = "", Description = "default", Type = "" },
                    new Medicament { IdMedicament = 3, Name = "", Description = "default", Type = "" },
                    new Medicament { IdMedicament = 4, Name = "", Description = "default", Type = "" },
                    new Medicament { IdMedicament = 5, Name = "", Description = "default", Type = "" }
                ) ;
        }
    }
}
