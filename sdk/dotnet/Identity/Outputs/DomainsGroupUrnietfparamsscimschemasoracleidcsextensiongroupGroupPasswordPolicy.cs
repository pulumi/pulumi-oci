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
    public sealed class DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy
    {
        /// <summary>
        /// (Updatable) PasswordPolicy Name
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// (Updatable) PasswordPolicy priority
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        public readonly int? Priority;
        /// <summary>
        /// (Updatable) PasswordPolicy URI
        /// 
        /// **Added In:** 20.1.3
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
        /// (Updatable) The ID of the PasswordPolicy.
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: true
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: true
        /// * returned: always
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Value;

        [OutputConstructor]
        private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupPasswordPolicy(
            string? name,

            int? priority,

            string? @ref,

            string value)
        {
            Name = name;
            Priority = priority;
            Ref = @ref;
            Value = value;
        }
    }
}
