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
    public sealed class DomainsAppSignonPolicy
    {
        /// <summary>
        /// (Updatable) URI of the policy.
        /// 
        /// **Deprecated Since: 17.3.4**
        /// 
        /// **SCIM++ Properties:**
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
        /// (Updatable) Identifier of the Policy.
        /// 
        /// **Deprecated Since: 17.3.4**
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsAppSignonPolicy(
            string? @ref,

            string value)
        {
            Ref = @ref;
            Value = value;
        }
    }
}
