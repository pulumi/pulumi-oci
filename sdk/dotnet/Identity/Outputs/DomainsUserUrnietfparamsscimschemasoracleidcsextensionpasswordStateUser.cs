// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Outputs
{

    [OutputType]
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUser
    {
        /// <summary>
        /// (Updatable) Applicable Password Policy
        /// </summary>
        public readonly Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicy? ApplicablePasswordPolicy;
        /// <summary>
        /// (Updatable) Indicates that the current password MAY NOT be changed and all other password expiry settings SHALL be ignored
        /// </summary>
        public readonly bool? CantChange;
        /// <summary>
        /// (Updatable) Indicates that the password expiry policy will not be applied for the current Resource
        /// </summary>
        public readonly bool? CantExpire;
        /// <summary>
        /// (Updatable) Indicates whether user password is expired. If this value is false, password expiry will still be evaluated during user login.
        /// </summary>
        public readonly bool? Expired;
        /// <summary>
        /// (Updatable) A DateTime that specifies the date and time when last failed password validation was set
        /// </summary>
        public readonly string? LastFailedValidationDate;
        /// <summary>
        /// (Updatable) A DateTime that specifies the date and time when the current password was set
        /// </summary>
        public readonly string? LastSuccessfulSetDate;
        /// <summary>
        /// (Updatable) A DateTime that specifies the date and time when last successful password validation was set
        /// </summary>
        public readonly string? LastSuccessfulValidationDate;
        /// <summary>
        /// (Updatable) Indicates that the subject password value MUST change on next login. If not changed, typically the account is locked. The value may be set indirectly when the subject's current password expires or directly set by an administrator.
        /// </summary>
        public readonly bool? MustChange;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUser(
            Outputs.DomainsUserUrnietfparamsscimschemasoracleidcsextensionpasswordStateUserApplicablePasswordPolicy? applicablePasswordPolicy,

            bool? cantChange,

            bool? cantExpire,

            bool? expired,

            string? lastFailedValidationDate,

            string? lastSuccessfulSetDate,

            string? lastSuccessfulValidationDate,

            bool? mustChange)
        {
            ApplicablePasswordPolicy = applicablePasswordPolicy;
            CantChange = cantChange;
            CantExpire = cantExpire;
            Expired = expired;
            LastFailedValidationDate = lastFailedValidationDate;
            LastSuccessfulSetDate = lastSuccessfulSetDate;
            LastSuccessfulValidationDate = lastSuccessfulValidationDate;
            MustChange = mustChange;
        }
    }
}