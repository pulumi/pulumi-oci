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
    public sealed class GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupResult
    {
        /// <summary>
        /// A list of appRoles that the user belongs to, either thorough direct membership, nested groups, or dynamically calculated
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRoleResult> AppRoles;
        /// <summary>
        /// Source from which this group got created.
        /// </summary>
        public readonly string CreationMechanism;
        /// <summary>
        /// Group description
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// Grants assigned to group
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrantResult> Grants;
        /// <summary>
        /// Group owners
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwnerResult> Owners;
        /// <summary>
        /// Password Policy associated with this Group.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicyResult> PasswordPolicies;
        /// <summary>
        /// The entity that created this Group.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppResult> SyncedFromApps;

        [OutputConstructor]
        private GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupResult(
            ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupAppRoleResult> appRoles,

            string creationMechanism,

            string description,

            ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupGrantResult> grants,

            ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupOwnerResult> owners,

            ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicyResult> passwordPolicies,

            ImmutableArray<Outputs.GetDomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppResult> syncedFromApps)
        {
            AppRoles = appRoles;
            CreationMechanism = creationMechanism;
            Description = description;
            Grants = grants;
            Owners = owners;
            PasswordPolicies = passwordPolicies;
            SyncedFromApps = syncedFromApps;
        }
    }
}
