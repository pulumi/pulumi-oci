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
    public sealed class DomainsDynamicResourceGroupGrant
    {
        /// <summary>
        /// (Updatable) App identifier
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsAddedSinceVersion: 3
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? AppId;
        /// <summary>
        /// (Updatable) Each value of grantMechanism indicates how (or by what component) some App (or App-Entitlement) was granted. A customer or the UI should use only grantMechanism values that start with 'ADMINISTRATOR':
        /// * 'ADMINISTRATOR_TO_USER' is for a direct grant to a specific User.
        /// * 'ADMINISTRATOR_TO_GROUP' is for a grant to a specific Group, which results in indirect grants to Users who are members of that Group.
        /// * 'ADMINISTRATOR_TO_APP' is for a grant to a specific App.  The grantee (client) App gains access to the granted (server) App.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsAddedSinceVersion: 3
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? GrantMechanism;
        /// <summary>
        /// (Updatable) Grant URI
        /// 
        /// **SCIM++ Properties:**
        /// * idcsAddedSinceVersion: 3
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: reference
        /// * uniqueness: none
        /// </summary>
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) Grant identifier
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsAddedSinceVersion: 3
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Value;

        [OutputConstructor]
        private DomainsDynamicResourceGroupGrant(
            string? appId,

            string? grantMechanism,

            string? @ref,

            string? value)
        {
            AppId = appId;
            GrantMechanism = grantMechanism;
            Ref = @ref;
            Value = value;
        }
    }
}
