using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Sales_systemCore.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sales_system_db
{
    public class SalesDbContext:IdentityDbContext<SalesUser>
    {
        public SalesDbContext(DbContextOptions<SalesDbContext>options):base(options)
        {

        }

    }
}
