// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudBridge.Outputs
{

    [OutputType]
    public sealed class AssetComputeScsiController
    {
        /// <summary>
        /// (Updatable) Provides a label and summary information for the device.
        /// </summary>
        public readonly string? Label;
        /// <summary>
        /// (Updatable) Shared bus.
        /// </summary>
        public readonly string? SharedBus;
        /// <summary>
        /// (Updatable) The unit number of the SCSI controller.
        /// </summary>
        public readonly int? UnitNumber;

        [OutputConstructor]
        private AssetComputeScsiController(
            string? label,

            string? sharedBus,

            int? unitNumber)
        {
            Label = label;
            SharedBus = sharedBus;
            UnitNumber = unitNumber;
        }
    }
}
