// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class GetBdsInstanceMetastoreConfigsBdsMetastoreConfigurationResult
    {
        public readonly int ActivateTrigger;
        /// <summary>
        /// The ID of the API key that is associated with the external metastore in the metastore configuration
        /// </summary>
        public readonly string BdsApiKeyId;
        public readonly string BdsApiKeyPassphrase;
        /// <summary>
        /// The OCID of the cluster.
        /// </summary>
        public readonly string BdsInstanceId;
        public readonly string ClusterAdminPassword;
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The ID of the metastore configuration
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the Data Catalog metastore in the metastore configuration
        /// </summary>
        public readonly string MetastoreId;
        /// <summary>
        /// The type of the metastore in the metastore configuration
        /// </summary>
        public readonly string MetastoreType;
        /// <summary>
        /// The lifecycle state of the metastore in the metastore configuration
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time when the configuration was created, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time when the configuration was updated, shown as an RFC 3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetBdsInstanceMetastoreConfigsBdsMetastoreConfigurationResult(
            int activateTrigger,

            string bdsApiKeyId,

            string bdsApiKeyPassphrase,

            string bdsInstanceId,

            string clusterAdminPassword,

            string displayName,

            string id,

            string metastoreId,

            string metastoreType,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            ActivateTrigger = activateTrigger;
            BdsApiKeyId = bdsApiKeyId;
            BdsApiKeyPassphrase = bdsApiKeyPassphrase;
            BdsInstanceId = bdsInstanceId;
            ClusterAdminPassword = clusterAdminPassword;
            DisplayName = displayName;
            Id = id;
            MetastoreId = metastoreId;
            MetastoreType = metastoreType;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
