using Sales_systemCore.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sales_systemCore.Interfaces
{
    public interface IAuthService
    {
        Task<AuthDto> RegisterAsync(RegisterDto model);
        Task<AuthDto> GetTokenAsync(TokenRequestDto model);
        Task<string> AddRoleAsync(AddRoleDto model);
        Task<AuthDto> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);

    }
}
