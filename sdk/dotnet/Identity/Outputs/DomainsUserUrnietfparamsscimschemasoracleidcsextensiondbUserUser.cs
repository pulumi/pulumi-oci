// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser
    {
        /// <summary>
        /// (Updatable) DB global roles to which the user is granted access.
        /// </summary>
        public readonly ImmutableArray<string> DbGlobalRoles;
        /// <summary>
        /// (Updatable) DB domain level schema to which the user is granted access.
        /// </summary>
        public readonly string? DomainLevelSchema;
        /// <summary>
        /// (Updatable) DB instance level schema to which the user is granted access.
        /// </summary>
        public readonly string? InstanceLevelSchema;
        /// <summary>
        /// (Updatable) If true, indicates this is a database user.
        /// </summary>
        public readonly bool? IsDbUser;
        /// <summary>
        /// (Updatable) Password Verifiers for DB User.
        /// </summary>
        public readonly ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier> PasswordVerifiers;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUser(
            ImmutableArray<string> dbGlobalRoles,

            string? domainLevelSchema,

            string? instanceLevelSchema,

            bool? isDbUser,

            ImmutableArray<Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensiondbUserUserPasswordVerifier> passwordVerifiers)
        {
            DbGlobalRoles = dbGlobalRoles;
            DomainLevelSchema = domainLevelSchema;
            InstanceLevelSchema = instanceLevelSchema;
            IsDbUser = isDbUser;
            PasswordVerifiers = passwordVerifiers;
        }
    }
}