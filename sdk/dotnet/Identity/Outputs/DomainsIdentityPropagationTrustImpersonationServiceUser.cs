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
    public sealed class DomainsIdentityPropagationTrustImpersonationServiceUser
    {
        /// <summary>
        /// (Updatable) The OCID of the Service User.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Ocid;
        public readonly string? Ref;
        /// <summary>
        /// (Updatable) The rule expression to be used for matching the inbound token for impersonation.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Rule;
        /// <summary>
        /// (Updatable) The ID of the Service User.
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
        private DomainsIdentityPropagationTrustImpersonationServiceUser(
            string? ocid,

            string? @ref,

            string rule,

            string value)
        {
            Ocid = ocid;
            Ref = @ref;
            Rule = rule;
            Value = value;
        }
    }
}
