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
    public sealed class DomainsIdentityProviderJitUserProvGroupMapping
    {
        /// <summary>
        /// (Updatable) IDP Group Name
        /// 
        /// **Added In:** 2205120021
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * type: string
        /// </summary>
        public readonly string IdpGroup;
        /// <summary>
        /// (Updatable) Group URI
        /// 
        /// **Added In:** 2205120021
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: default
        /// * type: reference
        /// </summary>
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) Domain Group
        /// 
        /// **Added In:** 2205120021
        /// 
        /// **SCIM++ Properties:**
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * idcsSearchable: true
        /// * type: string
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsIdentityProviderJitUserProvGroupMapping(
            string idpGroup,

            string? @ref,

            string value)
        {
            IdpGroup = idpGroup;
            Ref = @ref;
            Value = value;
        }
    }
}
