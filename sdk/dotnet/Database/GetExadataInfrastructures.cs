// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetExadataInfrastructures
    {
        /// <summary>
        /// This data source provides the list of Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the Exadata infrastructure resources in the specified compartment. Applies to Exadata Cloud@Customer instances only.
        /// To list the Exadata Cloud Service infrastructure resources in a compartment, use the  [ListCloudExadataInfrastructures](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudExadataInfrastructure/ListCloudExadataInfrastructures) operation.
        /// </summary>
        public static Task<GetExadataInfrastructuresResult> InvokeAsync(GetExadataInfrastructuresArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetExadataInfrastructuresResult>("oci:Database/getExadataInfrastructures:getExadataInfrastructures", args ?? new GetExadataInfrastructuresArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the Exadata infrastructure resources in the specified compartment. Applies to Exadata Cloud@Customer instances only.
        /// To list the Exadata Cloud Service infrastructure resources in a compartment, use the  [ListCloudExadataInfrastructures](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudExadataInfrastructure/ListCloudExadataInfrastructures) operation.
        /// </summary>
        public static Output<GetExadataInfrastructuresResult> Invoke(GetExadataInfrastructuresInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetExadataInfrastructuresResult>("oci:Database/getExadataInfrastructures:getExadataInfrastructures", args ?? new GetExadataInfrastructuresInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Exadata Infrastructures in Oracle Cloud Infrastructure Database service.
        /// 
        /// Lists the Exadata infrastructure resources in the specified compartment. Applies to Exadata Cloud@Customer instances only.
        /// To list the Exadata Cloud Service infrastructure resources in a compartment, use the  [ListCloudExadataInfrastructures](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudExadataInfrastructure/ListCloudExadataInfrastructures) operation.
        /// </summary>
        public static Output<GetExadataInfrastructuresResult> Invoke(GetExadataInfrastructuresInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetExadataInfrastructuresResult>("oci:Database/getExadataInfrastructures:getExadataInfrastructures", args ?? new GetExadataInfrastructuresInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetExadataInfrastructuresArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetExadataInfrastructuresFilterArgs>? _filters;
        public List<Inputs.GetExadataInfrastructuresFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetExadataInfrastructuresFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetExadataInfrastructuresArgs()
        {
        }
        public static new GetExadataInfrastructuresArgs Empty => new GetExadataInfrastructuresArgs();
    }

    public sealed class GetExadataInfrastructuresInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the entire display name given. The match is not case sensitive.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetExadataInfrastructuresFilterInputArgs>? _filters;
        public InputList<Inputs.GetExadataInfrastructuresFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetExadataInfrastructuresFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetExadataInfrastructuresInvokeArgs()
        {
        }
        public static new GetExadataInfrastructuresInvokeArgs Empty => new GetExadataInfrastructuresInvokeArgs();
    }


    [OutputType]
    public sealed class GetExadataInfrastructuresResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The user-friendly name for the Exadata Cloud@Customer infrastructure. The name does not need to be unique.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The list of exadata_infrastructures.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetExadataInfrastructuresExadataInfrastructureResult> ExadataInfrastructures;
        public readonly ImmutableArray<Outputs.GetExadataInfrastructuresFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current lifecycle state of the Exadata infrastructure.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetExadataInfrastructuresResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetExadataInfrastructuresExadataInfrastructureResult> exadataInfrastructures,

            ImmutableArray<Outputs.GetExadataInfrastructuresFilterResult> filters,

            string id,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            ExadataInfrastructures = exadataInfrastructures;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
