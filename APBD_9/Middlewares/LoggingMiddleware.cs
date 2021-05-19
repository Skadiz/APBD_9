using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace DoctorPatientAPI.Middlewares
{
    public class LoggingMiddleware
    {
        private readonly RequestDelegate _next;

        public LoggingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            context.Request.EnableBuffering();
            var request = context.Request;
            var method = request.Method;
            var path = request.Path;
            var query = HttpUtility.UrlDecode(request.QueryString.ToString());
            string body;


            using (var stream = new MemoryStream())
            using (var reader= new StreamReader(stream, Encoding.UTF8, true, 1024, true))
            {
                await request.Body.CopyToAsync(stream);
                body = await reader.ReadToEndAsync();
                stream.Seek(0, SeekOrigin.Begin);
                request.Body.Seek(0, SeekOrigin.Begin);
            }


            using (StreamWriter sw = new StreamWriter("logs.txt", true, Encoding.Default))
            {
               
                sw.WriteLine($"Method: {method}");
                sw.WriteLine($"Path: {path}");
                sw.WriteLine($"Body: {body}");
                sw.WriteLine($"Query: {query}");
            }

            try
            {
                await _next(context);
            }
            catch (Exception exc)
            {
                context.Response.StatusCode = 500;
                await context.Response.WriteAsync("Unexpected problem!");
            }

            

        }
    }
}