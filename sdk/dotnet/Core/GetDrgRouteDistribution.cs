// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetDrgRouteDistribution
    {
        /// <summary>
        /// This data source provides details about a specific Drg Route Distribution resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified route distribution's information.
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
        ///     var testDrgRouteDistribution = Oci.Core.GetDrgRouteDistribution.Invoke(new()
        ///     {
        ///         DrgRouteDistributionId = oci_core_drg_route_distribution.Test_drg_route_distribution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDrgRouteDistributionResult> InvokeAsync(GetDrgRouteDistributionArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDrgRouteDistributionResult>("oci:Core/getDrgRouteDistribution:getDrgRouteDistribution", args ?? new GetDrgRouteDistributionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Drg Route Distribution resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the specified route distribution's information.
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
        ///     var testDrgRouteDistribution = Oci.Core.GetDrgRouteDistribution.Invoke(new()
        ///     {
        ///         DrgRouteDistributionId = oci_core_drg_route_distribution.Test_drg_route_distribution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDrgRouteDistributionResult> Invoke(GetDrgRouteDistributionInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDrgRouteDistributionResult>("oci:Core/getDrgRouteDistribution:getDrgRouteDistribution", args ?? new GetDrgRouteDistributionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDrgRouteDistributionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
        /// </summary>
        [Input("drgRouteDistributionId", required: true)]
        public string DrgRouteDistributionId { get; set; } = null!;

        public GetDrgRouteDistributionArgs()
        {
        }
        public static new GetDrgRouteDistributionArgs Empty => new GetDrgRouteDistributionArgs();
    }

    public sealed class GetDrgRouteDistributionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route distribution.
        /// </summary>
        [Input("drgRouteDistributionId", required: true)]
        public Input<string> DrgRouteDistributionId { get; set; } = null!;

        public GetDrgRouteDistributionInvokeArgs()
        {
        }
        public static new GetDrgRouteDistributionInvokeArgs Empty => new GetDrgRouteDistributionInvokeArgs();
    }


    [OutputType]
    public sealed class GetDrgRouteDistributionResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the route distribution.
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
        /// Whether this distribution defines how routes get imported into route tables or exported through DRG attachments.
        /// </summary>
        public readonly string DistributionType;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG that contains this route distribution.
        /// </summary>
        public readonly string DrgId;
        public readonly string DrgRouteDistributionId;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The route distribution's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The route distribution's current state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the route distribution was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetDrgRouteDistributionResult(
            string compartmentId,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            string distributionType,

            string drgId,

            string drgRouteDistributionId,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            string state,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DistributionType = distributionType;
            DrgId = drgId;
            DrgRouteDistributionId = drgRouteDistributionId;
            FreeformTags = freeformTags;
            Id = id;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}