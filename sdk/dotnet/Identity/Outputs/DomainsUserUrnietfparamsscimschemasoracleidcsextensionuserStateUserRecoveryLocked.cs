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
    public sealed class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserRecoveryLocked
    {
        /// <summary>
        /// (Updatable) The date and time that the current resource was locked
        /// </summary>
        public readonly string? LockDate;
        /// <summary>
        /// (Updatable) Indicates that the rev is locked
        /// </summary>
        public readonly bool? On;

        [OutputConstructor]
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserStateUserRecoveryLocked(
            string? lockDate,

            bool? on)
        {
            LockDate = lockDate;
            On = on;
        }
    }
}