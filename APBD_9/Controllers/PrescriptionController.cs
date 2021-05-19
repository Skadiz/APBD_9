using DoctorPatientAPI.Models;
using DoctorPatientAPI.Models.DTOs.Response;
using DoctorPatientAPI.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoctorPatientAPI.Controllers
{
    [Route("api/prescription")]
    [ApiController]
    public class PrescriptionController : ControllerBase
    {
        private MainDbContext _context;

        public PrescriptionController(MainDbContext context)
        {
            _context = context;
        }

        [HttpGet("{index}")]
        public async Task<IActionResult> GetPrescription(string index)
        {
            var prescription = await new PrescriptionDbService().GetPrescription(_context, index);
            return Ok(prescription);
        }
    }
}
