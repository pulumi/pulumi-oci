// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ContainerEngine.Outputs
{

    [OutputType]
    public sealed class GetAddonsAddonResult
    {
        /// <summary>
        /// The error info of the addon.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddonsAddonAddonErrorResult> AddonErrors;
        /// <summary>
        /// The name of the addon.
        /// </summary>
        public readonly string AddonName;
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        public readonly string ClusterId;
        /// <summary>
        /// Addon configuration details.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAddonsAddonConfigurationResult> Configurations;
        /// <summary>
        /// current installed version of the addon
        /// </summary>
        public readonly string CurrentInstalledVersion;
        public readonly bool RemoveAddonResourcesOnDelete;
        /// <summary>
        /// The state of the addon.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the cluster was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// selected addon version, or null indicates autoUpdate
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetAddonsAddonResult(
            ImmutableArray<Outputs.GetAddonsAddonAddonErrorResult> addonErrors,

            string addonName,

            string clusterId,

            ImmutableArray<Outputs.GetAddonsAddonConfigurationResult> configurations,

            string currentInstalledVersion,

            bool removeAddonResourcesOnDelete,

            string state,

            string timeCreated,

            string version)
        {
            AddonErrors = addonErrors;
            AddonName = addonName;
            ClusterId = clusterId;
            Configurations = configurations;
            CurrentInstalledVersion = currentInstalledVersion;
            RemoveAddonResourcesOnDelete = removeAddonResourcesOnDelete;
            State = state;
            TimeCreated = timeCreated;
            Version = version;
        }
    }
}