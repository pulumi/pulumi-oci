// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard.Outputs
{

    [OutputType]
    public sealed class GetDataSourcesDataSourceCollectionItemResult
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Details specific to the data source type.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionItemDataSourceDetailResult> DataSourceDetails;
        /// <summary>
        /// Information about the detector recipe and rule attached
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionItemDataSourceDetectorMappingInfoResult> DataSourceDetectorMappingInfos;
        /// <summary>
        /// A filter to return only resources their feedProvider matches the given DataSourceFeedProvider.
        /// </summary>
        public readonly string DataSourceFeedProvider;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Ocid for Data source
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Information about the region and status of query replication
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionItemRegionStatusDetailResult> RegionStatusDetails;
        /// <summary>
        /// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Status of data Source
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The date and time the Data source was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the Data source was updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDataSourcesDataSourceCollectionItemResult(
            string compartmentId,

            ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionItemDataSourceDetailResult> dataSourceDetails,

            ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionItemDataSourceDetectorMappingInfoResult> dataSourceDetectorMappingInfos,

            string dataSourceFeedProvider,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetDataSourcesDataSourceCollectionItemRegionStatusDetailResult> regionStatusDetails,

            string state,

            string status,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DataSourceDetails = dataSourceDetails;
            DataSourceDetectorMappingInfos = dataSourceDetectorMappingInfos;
            DataSourceFeedProvider = dataSourceFeedProvider;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            RegionStatusDetails = regionStatusDetails;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}