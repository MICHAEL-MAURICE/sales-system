using AutoMapper;
using Sales_systemCore.Dtos;
using Sales_systemCore.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sales_systemCore.Helpers
{
    public  class MappingProfile:Profile
    {

        public MappingProfile()
        {
            CreateMap<RegisterDto, SalesUser>();
        }
    }
}
