using AutoMapper;
using IdentityServer4.EntityFramework.Mappers;

namespace JPProject.Admin.EntityFramework.Repository.Repository
{
    /// <summary>
    /// Mappers to help convert
    ///     IdentityServer4.Models > IdentityServer4.Entities
    ///     IdentityServer4.Entities > IdentityServer4.Model
    /// </summary>
    public static class ModelMappers
    {
        static ModelMappers()
        {
            Mapper = new MapperConfiguration(cfg =>
                {
                    cfg.AddProfile<ApiResourceMapperProfile>();
                    cfg.AddProfile<IdentityResourceMapperProfile>();
                    cfg.AddProfile<ClientMapperProfile>();
                    cfg.AddProfile<PersistedGrantMapperProfile>();
                })
                .CreateMapper();
        }

        internal static IMapper Mapper { get; }

    }

}