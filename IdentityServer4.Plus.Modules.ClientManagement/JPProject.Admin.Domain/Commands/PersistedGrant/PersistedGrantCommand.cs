using System;
using System.Collections.Generic;
using System.Text;
using JPProject.Domain.Core.Commands;

namespace JPProject.Admin.Domain.Commands.PersistedGrant
{
    public abstract class PersistedGrantCommand : Command
    {
        public string Key { get; protected set; }
    }
}
