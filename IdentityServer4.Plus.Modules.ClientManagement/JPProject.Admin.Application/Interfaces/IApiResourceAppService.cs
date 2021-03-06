using IdentityServer4.Models;
using JPProject.Admin.Application.ViewModels;
using JPProject.Admin.Application.ViewModels.ApiResouceViewModels;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace JPProject.Admin.Application.Interfaces
{
    public interface IApiResourceAppService : IDisposable
    {
        Task<IEnumerable<ApiResourceListViewModel>> GetApiResources();
        Task<ApiResource> GetDetails(string name);
        Task<bool> Save(ApiResource model);
        Task<bool> Update(string id, ApiResource model);
        Task<bool> Remove(RemoveApiResourceViewModel model);
        Task<IEnumerable<Secret>> GetSecrets(string name);
        Task<bool> RemoveSecret(RemoveApiSecretViewModel model);
        Task<bool> SaveSecret(SaveApiSecretViewModel model);
        Task<IEnumerable<Scope>> GetScopes(string name);
        Task<bool> RemoveScope(RemoveApiScopeViewModel model);
        Task<bool> SaveScope(SaveApiScopeViewModel model);
    }
}