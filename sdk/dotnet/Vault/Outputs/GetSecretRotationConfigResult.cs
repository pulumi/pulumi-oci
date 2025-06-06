// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Vault.Outputs
{

    [OutputType]
    public sealed class GetSecretRotationConfigResult
    {
        /// <summary>
        /// Enables auto rotation, when set to true rotationInterval must be set.
        /// </summary>
        public readonly bool IsScheduledRotationEnabled;
        /// <summary>
        /// The time interval that indicates the frequency for rotating secret data, as described in ISO 8601 format. The minimum value is 1 day and maximum value is 360 days. For example, if you want to set the time interval for rotating a secret data as 30 days, the duration is expressed as "P30D."
        /// </summary>
        public readonly string RotationInterval;
        /// <summary>
        /// The TargetSystemDetails provides the targetSystem type and type-specific connection metadata
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSecretRotationConfigTargetSystemDetailResult> TargetSystemDetails;

        [OutputConstructor]
        private GetSecretRotationConfigResult(
            bool isScheduledRotationEnabled,

            string rotationInterval,

            ImmutableArray<Outputs.GetSecretRotationConfigTargetSystemDetailResult> targetSystemDetails)
        {
            IsScheduledRotationEnabled = isScheduledRotationEnabled;
            RotationInterval = rotationInterval;
            TargetSystemDetails = targetSystemDetails;
        }
    }
}
