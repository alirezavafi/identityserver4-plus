using JPProject.Admin.Domain.Commands.IdentityResource;

namespace JPProject.Admin.Domain.Validations.IdentityResource
{
    public class UpdateIdentityResourceCommandValidation : IdentityResourceValidation<UpdateIdentityResourceCommand>
    {
        public UpdateIdentityResourceCommandValidation()
        {
            ValidateName();
        }
    }
}