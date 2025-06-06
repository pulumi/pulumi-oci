// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement
{
    public static class GetExternalCluster
    {
        /// <summary>
        /// This data source provides details about a specific External Cluster resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external cluster specified by `externalClusterId`.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalCluster = Oci.DatabaseManagement.GetExternalCluster.Invoke(new()
        ///     {
        ///         ExternalClusterId = testExternalClusterOciDatabaseManagementExternalCluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetExternalClusterResult> InvokeAsync(GetExternalClusterArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExternalClusterResult>("oci:DatabaseManagement/getExternalCluster:getExternalCluster", args ?? new GetExternalClusterArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Cluster resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external cluster specified by `externalClusterId`.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalCluster = Oci.DatabaseManagement.GetExternalCluster.Invoke(new()
        ///     {
        ///         ExternalClusterId = testExternalClusterOciDatabaseManagementExternalCluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalClusterResult> Invoke(GetExternalClusterInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalClusterResult>("oci:DatabaseManagement/getExternalCluster:getExternalCluster", args ?? new GetExternalClusterInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific External Cluster resource in Oracle Cloud Infrastructure Database Management service.
        /// 
        /// Gets the details for the external cluster specified by `externalClusterId`.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExternalCluster = Oci.DatabaseManagement.GetExternalCluster.Invoke(new()
        ///     {
        ///         ExternalClusterId = testExternalClusterOciDatabaseManagementExternalCluster.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetExternalClusterResult> Invoke(GetExternalClusterInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExternalClusterResult>("oci:DatabaseManagement/getExternalCluster:getExternalCluster", args ?? new GetExternalClusterInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExternalClusterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
        /// </summary>
        [Input("externalClusterId", required: true)]
        public string ExternalClusterId { get; set; } = null!;

        public GetExternalClusterArgs()
        {
        }
        public static new GetExternalClusterArgs Empty => new GetExternalClusterArgs();
    }

    public sealed class GetExternalClusterInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
        /// </summary>
        [Input("externalClusterId", required: true)]
        public Input<string> ExternalClusterId { get; set; } = null!;

        public GetExternalClusterInvokeArgs()
        {
        }
        public static new GetExternalClusterInvokeArgs Empty => new GetExternalClusterInvokeArgs();
    }


    [OutputType]
    public sealed class GetExternalClusterResult
    {
        /// <summary>
        /// The additional details of the external cluster defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> AdditionalDetails;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The name of the external cluster.
        /// </summary>
        public readonly string ComponentName;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The user-friendly name for the external cluster. The name does not have to be unique.
        /// </summary>
        public readonly string DisplayName;
        public readonly string ExternalClusterId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external connector.
        /// </summary>
        public readonly string ExternalConnectorId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the cluster is a part of.
        /// </summary>
        public readonly string ExternalDbSystemId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The directory in which Oracle Grid Infrastructure is installed.
        /// </summary>
        public readonly string GridHome;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether the cluster is Oracle Flex Cluster or not.
        /// </summary>
        public readonly bool IsFlexCluster;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The list of network address configurations of the external cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalClusterNetworkConfigurationResult> NetworkConfigurations;
        /// <summary>
        /// The location of the Oracle Cluster Registry (OCR).
        /// </summary>
        public readonly string OcrFileLocation;
        /// <summary>
        /// The list of Single Client Access Name (SCAN) configurations of the external cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalClusterScanConfigurationResult> ScanConfigurations;
        /// <summary>
        /// The current lifecycle state of the external cluster.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the external cluster was created.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the external cluster was last updated.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The cluster version.
        /// </summary>
        public readonly string Version;
        /// <summary>
        /// The list of Virtual IP (VIP) configurations of the external cluster.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExternalClusterVipConfigurationResult> VipConfigurations;

        [OutputConstructor]
        private GetExternalClusterResult(
            ImmutableDictionary<string, string> additionalDetails,

            string compartmentId,

            string componentName,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string externalClusterId,

            string externalConnectorId,

            string externalDbSystemId,

            ImmutableDictionary<string, string> freeformTags,

            string gridHome,

            string id,

            bool isFlexCluster,

            string lifecycleDetails,

            ImmutableArray<Outputs.GetExternalClusterNetworkConfigurationResult> networkConfigurations,

            string ocrFileLocation,

            ImmutableArray<Outputs.GetExternalClusterScanConfigurationResult> scanConfigurations,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated,

            string version,

            ImmutableArray<Outputs.GetExternalClusterVipConfigurationResult> vipConfigurations)
        {
            AdditionalDetails = additionalDetails;
            CompartmentId = compartmentId;
            ComponentName = componentName;
            DefinedTags = definedTags;
            DisplayName = displayName;
            ExternalClusterId = externalClusterId;
            ExternalConnectorId = externalConnectorId;
            ExternalDbSystemId = externalDbSystemId;
            FreeformTags = freeformTags;
            GridHome = gridHome;
            Id = id;
            IsFlexCluster = isFlexCluster;
            LifecycleDetails = lifecycleDetails;
            NetworkConfigurations = networkConfigurations;
            OcrFileLocation = ocrFileLocation;
            ScanConfigurations = scanConfigurations;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            Version = version;
            VipConfigurations = vipConfigurations;
        }
    }
}
