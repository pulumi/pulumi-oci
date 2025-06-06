// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oda
{
    public static class GetOdaInstances
    {
        /// <summary>
        /// This data source provides the list of Oda Instances in Oracle Cloud Infrastructure Digital Assistant service.
        /// 
        /// Returns a page of Digital Assistant instances that belong to the specified
        /// compartment.
        /// 
        /// If the `opc-next-page` header appears in the response, then
        /// there are more items to retrieve. To get the next page in the subsequent
        /// GET request, include the header's value as the `page` query parameter.
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
        ///     var testOdaInstances = Oci.Oda.GetOdaInstances.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = odaInstanceDisplayName,
        ///         State = odaInstanceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOdaInstancesResult> InvokeAsync(GetOdaInstancesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOdaInstancesResult>("oci:Oda/getOdaInstances:getOdaInstances", args ?? new GetOdaInstancesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Oda Instances in Oracle Cloud Infrastructure Digital Assistant service.
        /// 
        /// Returns a page of Digital Assistant instances that belong to the specified
        /// compartment.
        /// 
        /// If the `opc-next-page` header appears in the response, then
        /// there are more items to retrieve. To get the next page in the subsequent
        /// GET request, include the header's value as the `page` query parameter.
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
        ///     var testOdaInstances = Oci.Oda.GetOdaInstances.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = odaInstanceDisplayName,
        ///         State = odaInstanceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOdaInstancesResult> Invoke(GetOdaInstancesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOdaInstancesResult>("oci:Oda/getOdaInstances:getOdaInstances", args ?? new GetOdaInstancesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Oda Instances in Oracle Cloud Infrastructure Digital Assistant service.
        /// 
        /// Returns a page of Digital Assistant instances that belong to the specified
        /// compartment.
        /// 
        /// If the `opc-next-page` header appears in the response, then
        /// there are more items to retrieve. To get the next page in the subsequent
        /// GET request, include the header's value as the `page` query parameter.
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
        ///     var testOdaInstances = Oci.Oda.GetOdaInstances.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = odaInstanceDisplayName,
        ///         State = odaInstanceState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOdaInstancesResult> Invoke(GetOdaInstancesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOdaInstancesResult>("oci:Oda/getOdaInstances:getOdaInstances", args ?? new GetOdaInstancesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOdaInstancesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// List the Digital Assistant instances that belong to this compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// List only the information for the Digital Assistant instance with this user-friendly name. These names don't have to be unique and may change.  Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetOdaInstancesFilterArgs>? _filters;
        public List<Inputs.GetOdaInstancesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOdaInstancesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// List only the Digital Assistant instances that are in this lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetOdaInstancesArgs()
        {
        }
        public static new GetOdaInstancesArgs Empty => new GetOdaInstancesArgs();
    }

    public sealed class GetOdaInstancesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// List the Digital Assistant instances that belong to this compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// List only the information for the Digital Assistant instance with this user-friendly name. These names don't have to be unique and may change.  Example: `My new resource`
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetOdaInstancesFilterInputArgs>? _filters;
        public InputList<Inputs.GetOdaInstancesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOdaInstancesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// List only the Digital Assistant instances that are in this lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetOdaInstancesInvokeArgs()
        {
        }
        public static new GetOdaInstancesInvokeArgs Empty => new GetOdaInstancesInvokeArgs();
    }


    [OutputType]
    public sealed class GetOdaInstancesResult
    {
        /// <summary>
        /// Identifier of the compartment that the instance belongs to.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// User-defined name for the Digital Assistant instance. Avoid entering confidential information. You can change this value.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOdaInstancesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of oda_instances.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOdaInstancesOdaInstanceResult> OdaInstances;
        /// <summary>
        /// The current state of the Digital Assistant instance.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetOdaInstancesResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetOdaInstancesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetOdaInstancesOdaInstanceResult> odaInstances,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OdaInstances = odaInstances;
            State = state;
        }
    }
}
