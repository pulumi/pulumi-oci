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
    public sealed class DomainsUserEmail
    {
        /// <summary>
        /// (Updatable) Pending e-mail address verification
        /// 
        /// **Added In:** 19.1.4
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
        public readonly string? PendingVerificationData;
        /// <summary>
        /// (Updatable) A Boolean value that indicates whether the email address is the primary email address. The primary attribute value 'true' MUST appear no more than once.
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
        /// (Updatable) A Boolean value that indicates whether the email address is the secondary email address. The secondary attribute value 'true' MUST appear no more than once.
        /// 
        /// **Added In:** 18.2.6
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
        public readonly bool? Secondary;
        /// <summary>
        /// (Updatable) Type of email address
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
        /// (Updatable) Email address
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
        /// (Updatable) A Boolean value that indicates whether or not the e-mail address is verified
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
        public readonly bool? Verified;

        [OutputConstructor]
        private DomainsUserEmail(
            string? pendingVerificationData,

            bool? primary,

            bool? secondary,

            string type,

            string value,

            bool? verified)
        {
            PendingVerificationData = pendingVerificationData;
            Primary = primary;
            Secondary = secondary;
            Type = type;
            Value = value;
            Verified = verified;
        }
    }
}
