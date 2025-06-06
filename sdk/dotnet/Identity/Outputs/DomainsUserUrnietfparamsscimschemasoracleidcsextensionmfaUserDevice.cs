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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice
    {
        /// <summary>
        /// (Updatable) The authentication method.
        /// 
        /// **Added In:** 2009232244
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? AuthenticationMethod;
        /// <summary>
        /// (Updatable) A human readable name, primarily used for display purposes. READ-ONLY.
        /// 
        /// **Added In:** 18.3.6
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Display;
        /// <summary>
        /// (Updatable) The device authentication factor status.
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? FactorStatus;
        /// <summary>
        /// (Updatable) The device authentication factor type.
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? FactorType;
        /// <summary>
        /// (Updatable) The last sync time for device.
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        public readonly string? LastSyncTime;
        /// <summary>
        /// (Updatable) The URI of the corresponding Device resource which belongs to user.
        /// 
        /// **Added In:** 18.3.6
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
        /// (Updatable) The device's status.
        /// 
        /// **Added In:** 18.4.2
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? Status;
        /// <summary>
        /// (Updatable) The third-party factor vendor name.
        /// 
        /// **Added In:** 2009232244
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: default
        /// * type: string
        /// * uniqueness: none
        /// </summary>
        public readonly string? ThirdPartyVendorName;
        /// <summary>
        /// (Updatable) The user's device identifier.
        /// 
        /// **Added In:** 18.3.6
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
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionmfaUserDevice(
            string? authenticationMethod,

            string? display,

            string? factorStatus,

            string? factorType,

            string? lastSyncTime,

            string? @ref,

            string? status,

            string? thirdPartyVendorName,

            string value)
        {
            AuthenticationMethod = authenticationMethod;
            Display = display;
            FactorStatus = factorStatus;
            FactorType = factorType;
            LastSyncTime = lastSyncTime;
            Ref = @ref;
            Status = status;
            ThirdPartyVendorName = thirdPartyVendorName;
            Value = value;
        }
    }
}
