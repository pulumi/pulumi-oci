// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetDrgRouteRule
    {
        /// <summary>
        /// This data source provides details about a specific Drg Route Table resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified DRG route table's information.
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
        ///     var testDrgRouteTable = Oci.Core.GetDrgRouteRule.Invoke(new()
        ///     {
        ///         DrgRouteTableId = oci_core_drg_route_table.Test_drg_route_table.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDrgRouteRuleResult> InvokeAsync(GetDrgRouteRuleArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDrgRouteRuleResult>("oci:Core/getDrgRouteRule:getDrgRouteRule", args ?? new GetDrgRouteRuleArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Drg Route Table resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified DRG route table's information.
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
        ///     var testDrgRouteTable = Oci.Core.GetDrgRouteRule.Invoke(new()
        ///     {
        ///         DrgRouteTableId = oci_core_drg_route_table.Test_drg_route_table.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDrgRouteRuleResult> Invoke(GetDrgRouteRuleInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDrgRouteRuleResult>("oci:Core/getDrgRouteRule:getDrgRouteRule", args ?? new GetDrgRouteRuleInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDrgRouteRuleArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
        /// </summary>
        [Input("drgRouteTableId", required: true)]
        public string DrgRouteTableId { get; set; } = null!;

        public GetDrgRouteRuleArgs()
        {
        }
        public static new GetDrgRouteRuleArgs Empty => new GetDrgRouteRuleArgs();
    }

    public sealed class GetDrgRouteRuleInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
        /// </summary>
        [Input("drgRouteTableId", required: true)]
        public Input<string> DrgRouteTableId { get; set; } = null!;

        public GetDrgRouteRuleInvokeArgs()
        {
        }
        public static new GetDrgRouteRuleInvokeArgs Empty => new GetDrgRouteRuleInvokeArgs();
    }


    [OutputType]
    public sealed class GetDrgRouteRuleResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment the DRG is in. The DRG route table is always in the same compartment as the DRG.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the DRG that contains this route table.
        /// </summary>
        public readonly string DrgId;
        public readonly string DrgRouteTableId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG route table.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the import route distribution used to specify how incoming route advertisements from referenced attachments are inserted into the DRG route table.
        /// </summary>
        public readonly string ImportDrgRouteDistributionId;
        /// <summary>
        /// If you want traffic to be routed using ECMP across your virtual circuits or IPSec tunnels to your on-premises network, enable ECMP on the DRG route table to which these attachments import routes.
        /// </summary>
        public readonly bool IsEcmpEnabled;
        public readonly bool RemoveImportTrigger;
        /// <summary>
        /// The DRG route table's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the DRG route table was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetDrgRouteRuleResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string drgId,

            string drgRouteTableId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string importDrgRouteDistributionId,

            bool isEcmpEnabled,

            bool removeImportTrigger,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DrgId = drgId;
            DrgRouteTableId = drgRouteTableId;
            FreeformTags = freeformTags;
            Id = id;
            ImportDrgRouteDistributionId = importDrgRouteDistributionId;
            IsEcmpEnabled = isEcmpEnabled;
            RemoveImportTrigger = removeImportTrigger;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}