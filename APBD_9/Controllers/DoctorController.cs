using DoctorPatientAPI.Models;
using DoctorPatientAPI.Models.DTOs.Request;
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
    [Route("api/doctors")]
    [ApiController]
    public class DoctorController : ControllerBase
    {
        private MainDbContext _context;

        public DoctorController(MainDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IActionResult> GetDoctors()
        {
            var doctors = await new DoctorDbService().GetDoctors(_context);
            return Ok(doctors);
        }

        [HttpPost]
        public async Task<IActionResult> PostDoctor(CreateDoctorRequestDTO doctorInput)
        {
            await new DoctorDbService().PostDoctor(_context ,doctorInput);
            return StatusCode(201);
        }

        [HttpPut("{index}")]
        public async Task<IActionResult> PutDoctor(CreateDoctorRequestDTO doctorInput, string index)
        {
            await new DoctorDbService().PutDoctor(_context, doctorInput, index);
            return NoContent();
        }

        [HttpDelete("{index}")]
        public async Task<IActionResult> DeleteDoctor(string index)
        {
            await new DoctorDbService().DeleteDoctor(_context, index);
            return NoContent();
        }
    }
}
