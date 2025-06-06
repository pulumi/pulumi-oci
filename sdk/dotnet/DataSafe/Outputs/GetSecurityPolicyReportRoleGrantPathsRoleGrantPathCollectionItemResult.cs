// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetSecurityPolicyReportRoleGrantPathsRoleGrantPathCollectionItemResult
    {
        /// <summary>
        /// The grant depth level of the indirect grant. An indirectly granted role/privilege is granted to the user through another role. The depth level indicates how deep a privilege is within the grant hierarchy.
        /// </summary>
        public readonly int DepthLevel;
        /// <summary>
        /// A filter to return only items that match the specified role.
        /// </summary>
        public readonly string GrantedRole;
        /// <summary>
        /// A filter to return only items that match the specified grantee.
        /// </summary>
        public readonly string Grantee;
        /// <summary>
        /// The unique key of a role grant.
        /// </summary>
        public readonly string Key;

        [OutputConstructor]
        private GetSecurityPolicyReportRoleGrantPathsRoleGrantPathCollectionItemResult(
            int depthLevel,

            string grantedRole,

            string grantee,

            string key)
        {
            DepthLevel = depthLevel;
            GrantedRole = grantedRole;
            Grantee = grantee;
            Key = key;
        }
    }
}
