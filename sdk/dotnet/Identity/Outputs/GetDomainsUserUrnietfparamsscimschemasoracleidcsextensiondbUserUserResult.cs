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
    public sealed class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserResult
    {
        /// <summary>
        /// DB global roles to which the user is granted access.
        /// </summary>
        public readonly ImmutableArray<string> DbGlobalRoles;
        /// <summary>
        /// DB domain level schema to which the user is granted access.
        /// </summary>
        public readonly string DomainLevelSchema;
        /// <summary>
        /// DB instance level schema to which the user is granted access.
        /// </summary>
        public readonly string InstanceLevelSchema;
        /// <summary>
        /// If true, indicates this is a database user.
        /// </summary>
        public readonly bool IsDbUser;
        /// <summary>
        /// Password Verifiers for DB User.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifierResult> PasswordVerifiers;

        [OutputConstructor]
        private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserResult(
            ImmutableArray<string> dbGlobalRoles,

            string domainLevelSchema,

            string instanceLevelSchema,

            bool isDbUser,

            ImmutableArray<Outputs.GetDomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifierResult> passwordVerifiers)
        {
            DbGlobalRoles = dbGlobalRoles;
            DomainLevelSchema = domainLevelSchema;
            InstanceLevelSchema = instanceLevelSchema;
            IsDbUser = isDbUser;
            PasswordVerifiers = passwordVerifiers;
        }
    }
}
