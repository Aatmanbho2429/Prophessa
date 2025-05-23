using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;
using Prophessa.Core.Response;
namespace Prophessa.Api.Controllers
{
    //[EnableCors("AllowAllHeaders")]
    [Authorize]
    public class BaseController : ControllerBase, IActionFilter
    {
        protected string _userId;
        protected string _guId;
        protected string _userEmail;
        protected int _userTypeId;
        protected string _companyId;
        protected int _roleId;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public BaseController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        [ApiExplorerSettings(IgnoreApi = true)]
        protected async Task<BaseResponse<T>> DelegateControllerCall<T>(Func<Task<BaseResponse<T>>> call)
        {
            BaseResponse<T> result;
            try
            {
                result = await call();
            }
            catch (Exception ex)
            {
                //AppTrace.Error(ex);
                //logger.Error("Exception :" + ex);
                result = new BaseResponse<T>()
                {
                    status = 0,
                    message = "Technical Error Occured",
                };
            }
            return result;
        }
        [ApiExplorerSettings(IgnoreApi = true)]
        public void OnActionExecuted(ActionExecutedContext context)
        {
            throw new NotImplementedException();
        }
        [ApiExplorerSettings(IgnoreApi = true)]
        public void OnActionExecuting(ActionExecutingContext context)
        {
            try
            {
                var identity = _httpContextAccessor.HttpContext.User.Identity as ClaimsIdentity;
                if (identity != null)
                {
                    var claims = identity.Claims.ToList();
                    if (claims.Count > 0)
                    {
                        _userId = claims.Where(x => x.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").First().Value;
                        _guId = claims.Where(x => x.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").First().Value;
                    }
                }
                else
                    throw new UnauthorizedAccessException();
            }
            catch (Exception ex)
            {
                //AppTrace.Error(ex);
                throw new Exception("HttpAccessor error : " + ex.Message + ex.StackTrace);
            }
        }
    }
}
