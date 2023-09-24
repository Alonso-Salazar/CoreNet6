using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace EvaluacionAlonsoSalazar.Helpers
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission { get; }

        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }

    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {           
            if (context.User.HasClaim(c =>
                (c.Type == ClaimTypes.Role && c.Value == "Global Admin") ||
                (c.Type == "Permiso" && c.Value == requirement.Permission)))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }

            return Task.CompletedTask;
        }
    }

}
