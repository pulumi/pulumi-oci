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
    public sealed class GetDomainsMyGroupsMyGroupMemberResult
    {
        /// <summary>
        /// The date and time that the member was added to the group.
        /// </summary>
        public readonly string DateAdded;
        /// <summary>
        /// App Display Name
        /// </summary>
        public readonly string Display;
        /// <summary>
        /// The membership OCID.
        /// </summary>
        public readonly string MembershipOcid;
        /// <summary>
        /// PasswordPolicy Name
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        /// </summary>
        public readonly string Ocid;
        /// <summary>
        /// App URI
        /// </summary>
        public readonly string Ref;
        /// <summary>
        /// The type of the entity that created this Group.
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// The ID of the App.
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private GetDomainsMyGroupsMyGroupMemberResult(
            string dateAdded,

            string display,

            string membershipOcid,

            string name,

            string ocid,

            string @ref,

            string type,

            string value)
        {
            DateAdded = dateAdded;
            Display = display;
            MembershipOcid = membershipOcid;
            Name = name;
            Ocid = ocid;
            Ref = @ref;
            Type = type;
            Value = value;
        }
    }
}
