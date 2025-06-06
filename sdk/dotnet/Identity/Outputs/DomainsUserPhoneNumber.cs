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
    public sealed class DomainsUserPhoneNumber
    {
        /// <summary>
        /// (Updatable) A human-readable name, primarily used for display purposes. READ ONLY
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Display;
        /// <summary>
        /// (Updatable) A Boolean value that indicates the 'primary' or preferred attribute value for this attribute--for example, the preferred phone number or primary phone number. The primary attribute value 'true' MUST appear no more than once.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? Primary;
        /// <summary>
        /// (Updatable) A label that indicates the attribute's function- for example, 'work', 'home', or 'mobile'
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Type;
        /// <summary>
        /// (Updatable) User's phone number
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: true
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string Value;
        /// <summary>
        /// (Updatable) A Boolean value that indicates if the phone number is verified.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: boolean
        /// * uniqueness: none
        /// </summary>
        public readonly bool? Verified;

        [OutputConstructor]
        private DomainsUserPhoneNumber(
            string? display,

            bool? primary,

            string type,

            string value,

            bool? verified)
        {
            Display = display;
            Primary = primary;
            Type = type;
            Value = value;
            Verified = verified;
        }
    }
}
