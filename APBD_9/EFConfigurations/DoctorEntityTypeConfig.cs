using DoctorPatientAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.EFConfigurations
{
    public class DoctorEntityTypeConfig : IEntityTypeConfiguration<Doctor>
    {
        public void Configure(EntityTypeBuilder<Doctor> builder)
        {
            builder.HasKey(e => e.IdDoctor);

            builder.Property(e => e.IdDoctor).ValueGeneratedNever();

            builder.Property(e => e.FirstName).IsRequired()
                                              .HasMaxLength(100);

            builder.Property(e => e.LastName).IsRequired()
                                             .HasMaxLength(150);

            builder.Property(e => e.Email).IsRequired()
                                          .HasMaxLength(120);
            // seed data
            builder.HasData(
                    new Doctor { IdDoctor = 1, FirstName = "Jan", LastName = "Kowak", Email = "jan@gmail.com" },
                    new Doctor { IdDoctor = 2, FirstName = "Ken", LastName = "Smith", Email = "ksmith@gmail.com" },
                    new Doctor { IdDoctor = 3, FirstName = "Alisa", LastName = "Kathe", Email = "alisacat@gmail.com" }
                ); 
        }
    }
}
