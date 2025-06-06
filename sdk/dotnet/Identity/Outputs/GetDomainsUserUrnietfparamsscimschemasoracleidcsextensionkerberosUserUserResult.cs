// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserResult
    {
        /// <summary>
        /// A list of kerberos realm users for an Oracle Identity Cloud Service User
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUserResult> RealmUsers;

        [OutputConstructor]
        private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserResult(ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionkerberosUserUserRealmUserResult> realmUsers)
        {
            RealmUsers = realmUsers;
        }
    }
}
