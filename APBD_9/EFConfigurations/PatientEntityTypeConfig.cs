using DoctorPatientAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.EFConfigurations
{
    public class PatientEntityTypeConfig : IEntityTypeConfiguration<Patient>
    {
        public void Configure(EntityTypeBuilder<Patient> builder)
        {
            builder.HasKey(e => e.IdPatient);

            builder.Property(e => e.IdPatient).ValueGeneratedNever();

            builder.Property(e => e.FirstName).IsRequired()
                                              .HasMaxLength(100);

            builder.Property(e => e.LastName).IsRequired()
                                             .HasMaxLength(150);

            builder.Property(e => e.Birthdate).IsRequired()
                                              .HasColumnType("datetime");
            // seed data
            builder.HasData(
                    new Patient { IdPatient = 1, FirstName = "Lolita", LastName = "Kowalski", Birthdate = DateTime.Now },
                    new Patient { IdPatient = 2, FirstName = "Kevin", LastName = "Kim", Birthdate = DateTime.Now },
                    new Patient { IdPatient = 3, FirstName = "Alisher", LastName = "Sabirov", Birthdate = DateTime.Now }
                );
        }
    }
}
