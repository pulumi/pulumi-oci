// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetSoftwareUpdate.Outputs
{

    [OutputType]
    public sealed class FsuCycleUpgradeDetails
    {
        /// <summary>
        /// (Updatable) Type of Exadata Fleet Update collection being upgraded.
        /// </summary>
        public readonly string CollectionType;
        /// <summary>
        /// (Updatable) Enables or disables the recompilation of invalid objects.
        /// </summary>
        public readonly bool? IsRecompileInvalidObjects;
        /// <summary>
        /// (Updatable) Enables or disables time zone upgrade. 
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly bool? IsTimeZoneUpgrade;

        [OutputConstructor]
        private FsuCycleUpgradeDetails(
            string collectionType,

            bool? isRecompileInvalidObjects,

            bool? isTimeZoneUpgrade)
        {
            CollectionType = collectionType;
            IsRecompileInvalidObjects = isRecompileInvalidObjects;
            IsTimeZoneUpgrade = isTimeZoneUpgrade;
        }
    }
}
