using JPProject.Admin.Domain.Commands.ApiResource;

namespace JPProject.Admin.Domain.Validations.ApiResource
{
    public class RemoveApiCommandValidation : ApiSecretValidation<RemoveApiSecretCommand>
    {
        public RemoveApiCommandValidation()
        {
            ValidateResourceName();
        }
    }
}