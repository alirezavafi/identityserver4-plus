using System.Threading.Tasks;

namespace SSO.Controllers
{
    public interface ISmsService
    {
        Task Send(OutgoingSms outgoingSms);
    }
}