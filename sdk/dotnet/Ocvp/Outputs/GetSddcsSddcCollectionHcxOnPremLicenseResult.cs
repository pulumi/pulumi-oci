// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Ocvp.Outputs
{

    [OutputType]
    public sealed class GetSddcsSddcCollectionHcxOnPremLicenseResult
    {
        /// <summary>
        /// HCX on-premise license key value.
        /// </summary>
        public readonly string ActivationKey;
        /// <summary>
        /// status of HCX on-premise license.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Name of the system that consumed the HCX on-premise license
        /// </summary>
        public readonly string SystemName;

        [OutputConstructor]
        private GetSddcsSddcCollectionHcxOnPremLicenseResult(
            string activationKey,

            string status,

            string systemName)
        {
            ActivationKey = activationKey;
            Status = status;
            SystemName = systemName;
        }
    }
}