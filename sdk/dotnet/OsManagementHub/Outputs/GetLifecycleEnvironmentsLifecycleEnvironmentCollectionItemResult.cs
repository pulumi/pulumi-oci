// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetLifecycleEnvironmentsLifecycleEnvironmentCollectionItemResult
    {
        /// <summary>
        /// A filter to return only profiles that match the given archType.
        /// </summary>
        public readonly string ArchType;
        /// <summary>
        /// The OCID of the compartment that contains the resources to list.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Software source description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return resources that match the given display names.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The OCID of the software source.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of managed instances specified lifecycle stage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLifecycleEnvironmentsLifecycleEnvironmentCollectionItemManagedInstanceIdResult> ManagedInstanceIds;
        /// <summary>
        /// A filter to return only profiles that match the given osFamily.
        /// </summary>
        public readonly string OsFamily;
        /// <summary>
        /// User specified list of lifecycle stages to be created for the lifecycle environment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLifecycleEnvironmentsLifecycleEnvironmentCollectionItemStageResult> Stages;
        /// <summary>
        /// A filter to return only the lifecycle environments that match the display name given.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the lifecycle environment was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the lifecycle environment was last modified. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeModified;
        /// <summary>
        /// The software source vendor name.
        /// </summary>
        public readonly string VendorName;

        [OutputConstructor]
        private GetLifecycleEnvironmentsLifecycleEnvironmentCollectionItemResult(
            string archType,

            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string description,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetLifecycleEnvironmentsLifecycleEnvironmentCollectionItemManagedInstanceIdResult> managedInstanceIds,

            string osFamily,

            ImmutableArray<Outputs.GetLifecycleEnvironmentsLifecycleEnvironmentCollectionItemStageResult> stages,

            string state,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeModified,

            string vendorName)
        {
            ArchType = archType;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            ManagedInstanceIds = managedInstanceIds;
            OsFamily = osFamily;
            Stages = stages;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeModified = timeModified;
            VendorName = vendorName;
        }
    }
}