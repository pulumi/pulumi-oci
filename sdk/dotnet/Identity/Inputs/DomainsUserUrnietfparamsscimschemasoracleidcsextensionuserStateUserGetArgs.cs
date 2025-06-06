// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The last failed login date.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * idcsAllowUpdatesInReadOnlyMode: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: request
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        [Input("lastFailedLoginDate")]
        public Input<string>? LastFailedLoginDate { get; set; }

        /// <summary>
        /// (Updatable) The last successful login date.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: true
        /// * idcsAllowUpdatesInReadOnlyMode: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: request
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        [Input("lastSuccessfulLoginDate")]
        public Input<string>? LastSuccessfulLoginDate { get; set; }

        /// <summary>
        /// (Updatable) A complex attribute that indicates an account is locked (blocking any new sessions).
        /// 
        /// **SCIM++ Properties:**
        /// * idcsCsvAttributeNameMappings: [[columnHeaderName:Locked, mapsTo:locked.on], [columnHeaderName:Locked Reason, mapsTo:locked.reason], [columnHeaderName:Locked Date, mapsTo:locked.lockDate]]
        /// * idcsSearchable: false
        /// * idcsAllowUpdatesInReadOnlyMode: true
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        [Input("locked")]
        public Input<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserLockedGetArgs>? Locked { get; set; }

        /// <summary>
        /// (Updatable) The number of failed login attempts. The value is reset to 0 after a successful login.
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * idcsAllowUpdatesInReadOnlyMode: true
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * idcsRequiresImmediateReadAfterWriteForAccessFlows: true
        /// * required: false
        /// * returned: request
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("loginAttempts")]
        public Input<int>? LoginAttempts { get; set; }

        /// <summary>
        /// (Updatable) The maximum number of concurrent sessions for a user.
        /// 
        /// **Added In:** 20.1.3
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsMaxValue: 999
        /// * idcsMinValue: 1
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("maxConcurrentSessions")]
        public Input<int>? MaxConcurrentSessions { get; set; }

        /// <summary>
        /// (Updatable) The previous successful login date.
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: request
        /// * type: dateTime
        /// * uniqueness: none
        /// </summary>
        [Input("previousSuccessfulLoginDate")]
        public Input<string>? PreviousSuccessfulLoginDate { get; set; }

        /// <summary>
        /// (Updatable) The number of failed recovery attempts. The value is reset to 0 after a successful login.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * idcsRequiresWriteForAccessFlows: true
        /// * required: false
        /// * returned: request
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("recoveryAttempts")]
        public Input<int>? RecoveryAttempts { get; set; }

        /// <summary>
        /// (Updatable) The number of failed account recovery enrollment attempts.
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readOnly
        /// * required: false
        /// * returned: request
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("recoveryEnrollAttempts")]
        public Input<int>? RecoveryEnrollAttempts { get; set; }

        /// <summary>
        /// (Updatable) A complex attribute that indicates a password recovery is locked (blocking any new sessions).
        /// 
        /// **Added In:** 19.1.4
        /// 
        /// **SCIM++ Properties:**
        /// * idcsSearchable: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: complex
        /// * uniqueness: none
        /// </summary>
        [Input("recoveryLocked")]
        public Input<Inputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserRecoveryLockedGetArgs>? RecoveryLocked { get; set; }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserGetArgs()
        {
        }
        public static new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserGetArgs Empty => new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserGetArgs();
    }
}
