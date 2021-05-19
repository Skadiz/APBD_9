using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace DoctorPatientAPI.Migrations
{
    public partial class AddedTables : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Doctors",
                columns: table => new
                {
                    IdDoctor = table.Column<int>(type: "int", nullable: false),
                    FirstName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    LastName = table.Column<string>(type: "nvarchar(150)", maxLength: 150, nullable: false),
                    Email = table.Column<string>(type: "nvarchar(120)", maxLength: 120, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Doctors", x => x.IdDoctor);
                });

            migrationBuilder.CreateTable(
                name: "Medicaments",
                columns: table => new
                {
                    IdMedicament = table.Column<int>(type: "int", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Type = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Medicaments", x => x.IdMedicament);
                });

            migrationBuilder.CreateTable(
                name: "Patients",
                columns: table => new
                {
                    IdPatient = table.Column<int>(type: "int", nullable: false),
                    FirstName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    LastName = table.Column<string>(type: "nvarchar(150)", maxLength: 150, nullable: false),
                    Birthdate = table.Column<DateTime>(type: "datetime", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Patients", x => x.IdPatient);
                });

            migrationBuilder.CreateTable(
                name: "Prescriptions",
                columns: table => new
                {
                    IdPrescription = table.Column<int>(type: "int", nullable: false),
                    Date = table.Column<DateTime>(type: "datetime", nullable: false),
                    DueDate = table.Column<DateTime>(type: "datetime", nullable: false),
                    IdPatient = table.Column<int>(type: "int", nullable: false),
                    IdDoctor = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Prescriptions", x => x.IdPrescription);
                    table.ForeignKey(
                        name: "FK_Prescriptions_Doctors_IdDoctor",
                        column: x => x.IdDoctor,
                        principalTable: "Doctors",
                        principalColumn: "IdDoctor",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Prescriptions_Patients_IdPatient",
                        column: x => x.IdPatient,
                        principalTable: "Patients",
                        principalColumn: "IdPatient",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Prescription_Medicaments",
                columns: table => new
                {
                    IdPrescription = table.Column<int>(type: "int", nullable: false),
                    IdMedicament = table.Column<int>(type: "int", nullable: false),
                    Dose = table.Column<int>(type: "int", nullable: true),
                    Details = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Prescription_Medicaments", x => x.IdPrescription);
                    table.ForeignKey(
                        name: "FK_Prescription_Medicaments_Medicaments_IdMedicament",
                        column: x => x.IdMedicament,
                        principalTable: "Medicaments",
                        principalColumn: "IdMedicament",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Prescription_Medicaments_Prescriptions_IdPrescription",
                        column: x => x.IdPrescription,
                        principalTable: "Prescriptions",
                        principalColumn: "IdPrescription",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.InsertData(
                table: "Doctors",
                columns: new[] { "IdDoctor", "Email", "FirstName", "LastName" },
                values: new object[,]
                {
                    { 1, "jan@gmail.com", "Jan", "Kowak" },
                    { 2, "ksmith@gmail.com", "Ken", "Smith" },
                    { 3, "alisacat@gmail.com", "Alisa", "Kathe" }
                });

            migrationBuilder.InsertData(
                table: "Medicaments",
                columns: new[] { "IdMedicament", "Description", "Name", "Type" },
                values: new object[,]
                {
                    { 1, "default", "", "" },
                    { 2, "default", "", "" },
                    { 3, "default", "", "" },
                    { 4, "default", "", "" },
                    { 5, "default", "", "" }
                });

            migrationBuilder.InsertData(
                table: "Patients",
                columns: new[] { "IdPatient", "Birthdate", "FirstName", "LastName" },
                values: new object[,]
                {
                    { 1, new DateTime(2021, 5, 4, 3, 23, 24, 881, DateTimeKind.Local).AddTicks(445), "Lolita", "Kowalski" },
                    { 2, new DateTime(2021, 5, 4, 3, 23, 24, 881, DateTimeKind.Local).AddTicks(9140), "Kevin", "Kim" },
                    { 3, new DateTime(2021, 5, 4, 3, 23, 24, 881, DateTimeKind.Local).AddTicks(9151), "Alisher", "Sabirov" }
                });

            migrationBuilder.InsertData(
                table: "Prescriptions",
                columns: new[] { "IdPrescription", "Date", "DueDate", "IdDoctor", "IdPatient" },
                values: new object[,]
                {
                    { 3, new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3643), new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3644), 3, 1 },
                    { 5, new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3648), new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3649), 1, 1 },
                    { 1, new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(1566), new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(2008), 2, 2 },
                    { 2, new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3637), new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3641), 1, 3 },
                    { 4, new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3645), new DateTime(2021, 5, 4, 3, 23, 24, 896, DateTimeKind.Local).AddTicks(3646), 2, 3 }
                });

            migrationBuilder.InsertData(
                table: "Prescription_Medicaments",
                columns: new[] { "IdPrescription", "Details", "Dose", "IdMedicament" },
                values: new object[,]
                {
                    { 3, "default", 10, 3 },
                    { 5, "default", 5, 5 },
                    { 1, "default", 3, 1 },
                    { 2, "default", null, 2 },
                    { 4, "default", null, 4 }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Prescription_Medicaments_IdMedicament",
                table: "Prescription_Medicaments",
                column: "IdMedicament");

            migrationBuilder.CreateIndex(
                name: "IX_Prescriptions_IdDoctor",
                table: "Prescriptions",
                column: "IdDoctor");

            migrationBuilder.CreateIndex(
                name: "IX_Prescriptions_IdPatient",
                table: "Prescriptions",
                column: "IdPatient");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Prescription_Medicaments");

            migrationBuilder.DropTable(
                name: "Medicaments");

            migrationBuilder.DropTable(
                name: "Prescriptions");

            migrationBuilder.DropTable(
                name: "Doctors");

            migrationBuilder.DropTable(
                name: "Patients");
        }
    }
}
