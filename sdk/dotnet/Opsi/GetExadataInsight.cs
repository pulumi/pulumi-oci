// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetExadataInsight
    {
        /// <summary>
        /// This data source provides details about a specific Exadata Insight resource in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets details of an Exadata insight.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExadataInsight = Oci.Opsi.GetExadataInsight.Invoke(new()
        ///     {
        ///         ExadataInsightId = oci_opsi_exadata_insight.Test_exadata_insight.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetExadataInsightResult> InvokeAsync(GetExadataInsightArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetExadataInsightResult>("oci:Opsi/getExadataInsight:getExadataInsight", args ?? new GetExadataInsightArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Exadata Insight resource in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets details of an Exadata insight.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testExadataInsight = Oci.Opsi.GetExadataInsight.Invoke(new()
        ///     {
        ///         ExadataInsightId = oci_opsi_exadata_insight.Test_exadata_insight.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetExadataInsightResult> Invoke(GetExadataInsightInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetExadataInsightResult>("oci:Opsi/getExadataInsight:getExadataInsight", args ?? new GetExadataInsightInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExadataInsightArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Exadata insight identifier
        /// </summary>
        [Input("exadataInsightId", required: true)]
        public string ExadataInsightId { get; set; } = null!;

        public GetExadataInsightArgs()
        {
        }
        public static new GetExadataInsightArgs Empty => new GetExadataInsightArgs();
    }

    public sealed class GetExadataInsightInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique Exadata insight identifier
        /// </summary>
        [Input("exadataInsightId", required: true)]
        public Input<string> ExadataInsightId { get; set; } = null!;

        public GetExadataInsightInvokeArgs()
        {
        }
        public static new GetExadataInsightInvokeArgs Empty => new GetExadataInsightInvokeArgs();
    }


    [OutputType]
    public sealed class GetExadataInsightResult
    {
        /// <summary>
        /// Compartment identifier of the Exadata insight resource
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// OPSI Enterprise Manager Bridge OCID
        /// </summary>
        public readonly string EnterpriseManagerBridgeId;
        /// <summary>
        /// Enterprise Manager Entity Display Name
        /// </summary>
        public readonly string EnterpriseManagerEntityDisplayName;
        /// <summary>
        /// Enterprise Manager Entity Unique Identifier
        /// </summary>
        public readonly string EnterpriseManagerEntityIdentifier;
        /// <summary>
        /// Enterprise Manager Entity Name
        /// </summary>
        public readonly string EnterpriseManagerEntityName;
        /// <summary>
        /// Enterprise Manager Entity Type
        /// </summary>
        public readonly string EnterpriseManagerEntityType;
        /// <summary>
        /// Enterprise Manager Unique Identifier
        /// </summary>
        public readonly string EnterpriseManagerIdentifier;
        /// <summary>
        /// Source of the Exadata system.
        /// </summary>
        public readonly string EntitySource;
        /// <summary>
        /// The user-friendly name for the Exadata system. The name does not have to be unique.
        /// </summary>
        public readonly string ExadataDisplayName;
        public readonly string ExadataInsightId;
        /// <summary>
        /// The Exadata system name. If the Exadata systems managed by Enterprise Manager, the name is unique amongst the Exadata systems managed by the same Enterprise Manager.
        /// </summary>
        public readonly string ExadataName;
        /// <summary>
        /// Exadata rack type.
        /// </summary>
        public readonly string ExadataRackType;
        /// <summary>
        /// Operations Insights internal representation of the the Exadata system type.
        /// </summary>
        public readonly string ExadataType;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// Exadata insight identifier
        /// </summary>
        public readonly string Id;
        public readonly bool IsAutoSyncEnabled;
        /// <summary>
        /// true if virtualization is used in the Exadata system
        /// </summary>
        public readonly bool IsVirtualizedExadata;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of the Exadata insight.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Indicates the status of an Exadata insight in Operations Insights
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> SystemTags;
        /// <summary>
        /// The time the the Exadata insight was first enabled. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the Exadata insight was updated. An RFC3339 formatted datetime string
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetExadataInsightResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string enterpriseManagerBridgeId,

            string enterpriseManagerEntityDisplayName,

            string enterpriseManagerEntityIdentifier,

            string enterpriseManagerEntityName,

            string enterpriseManagerEntityType,

            string enterpriseManagerIdentifier,

            string entitySource,

            string exadataDisplayName,

            string exadataInsightId,

            string exadataName,

            string exadataRackType,

            string exadataType,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isAutoSyncEnabled,

            bool isVirtualizedExadata,

            string lifecycleDetails,

            string state,

            string status,

            ImmutableDictionary<string, object> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            EnterpriseManagerBridgeId = enterpriseManagerBridgeId;
            EnterpriseManagerEntityDisplayName = enterpriseManagerEntityDisplayName;
            EnterpriseManagerEntityIdentifier = enterpriseManagerEntityIdentifier;
            EnterpriseManagerEntityName = enterpriseManagerEntityName;
            EnterpriseManagerEntityType = enterpriseManagerEntityType;
            EnterpriseManagerIdentifier = enterpriseManagerIdentifier;
            EntitySource = entitySource;
            ExadataDisplayName = exadataDisplayName;
            ExadataInsightId = exadataInsightId;
            ExadataName = exadataName;
            ExadataRackType = exadataRackType;
            ExadataType = exadataType;
            FreeformTags = freeformTags;
            Id = id;
            IsAutoSyncEnabled = isAutoSyncEnabled;
            IsVirtualizedExadata = isVirtualizedExadata;
            LifecycleDetails = lifecycleDetails;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}