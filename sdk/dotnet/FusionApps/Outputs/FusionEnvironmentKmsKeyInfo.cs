// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FusionApps.Outputs
{

    [OutputType]
    public sealed class FusionEnvironmentKmsKeyInfo
    {
        public readonly string? ActiveKeyId;
        public readonly string? ActiveKeyVersion;
        public readonly string? CurrentKeyLifecycleState;
        public readonly string? ScheduledKeyId;
        public readonly string? ScheduledKeyStatus;
        public readonly string? ScheduledKeyVersion;
        public readonly string? ScheduledLifecycleState;

        [OutputConstructor]
        private FusionEnvironmentKmsKeyInfo(
            string? activeKeyId,

            string? activeKeyVersion,

            string? currentKeyLifecycleState,

            string? scheduledKeyId,

            string? scheduledKeyStatus,

            string? scheduledKeyVersion,

            string? scheduledLifecycleState)
        {
            ActiveKeyId = activeKeyId;
            ActiveKeyVersion = activeKeyVersion;
            CurrentKeyLifecycleState = currentKeyLifecycleState;
            ScheduledKeyId = scheduledKeyId;
            ScheduledKeyStatus = scheduledKeyStatus;
            ScheduledKeyVersion = scheduledKeyVersion;
            ScheduledLifecycleState = scheduledLifecycleState;
        }
    }
}
