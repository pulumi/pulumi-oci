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
    public sealed class GetDomainsAppGrantResult
    {
        /// <summary>
        /// Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with 'ADMINISTRATOR':
        /// * 'ADMINISTRATOR_TO_USER' is for a direct grant to a specific User.
        /// * 'ADMINISTRATOR_TO_GROUP' is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
        /// * 'ADMINISTRATOR_TO_APP' is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
        /// </summary>
        public readonly string GrantMechanism;
        /// <summary>
        /// Grantee identifier
        /// </summary>
        public readonly string GranteeId;
        /// <summary>
        /// Grantee resource type. Allowed values are User and Group.
        /// </summary>
        public readonly string GranteeType;
        /// <summary>
        /// URI of the AppRole.
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// ID of the AppRole.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsAppGrantResult(
            string grantMechanism,

            string granteeId,

            string granteeType,

            string @ref,

            string value)
        {
            GrantMechanism = grantMechanism;
            GranteeId = granteeId;
            GranteeType = granteeType;
            Ref = @ref;
            Value = value;
        }
    }
}
