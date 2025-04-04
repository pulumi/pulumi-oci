// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.FleetAppsManagement.Outputs
{

    [OutputType]
    public sealed class GetPlatformConfigurationsPlatformConfigurationCollectionItemConfigCategoryDetailProductResult
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// unique PlatformConfiguration identifier
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetPlatformConfigurationsPlatformConfigurationCollectionItemConfigCategoryDetailProductResult(
            string displayName,

            string id)
        {
            DisplayName = displayName;
            Id = id;
        }
    }
}
