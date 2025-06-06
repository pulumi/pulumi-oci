// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetMlApplications
    {
        /// <summary>
        /// This data source provides the list of Ml Applications in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Returns a list of MlApplications.
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
        ///     var testMlApplications = Oci.DataScience.GetMlApplications.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = mlApplicationCompartmentIdInSubtree,
        ///         MlApplicationId = testMlApplication.Id,
        ///         Name = mlApplicationName,
        ///         State = mlApplicationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMlApplicationsResult> InvokeAsync(GetMlApplicationsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMlApplicationsResult>("oci:DataScience/getMlApplications:getMlApplications", args ?? new GetMlApplicationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ml Applications in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Returns a list of MlApplications.
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
        ///     var testMlApplications = Oci.DataScience.GetMlApplications.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = mlApplicationCompartmentIdInSubtree,
        ///         MlApplicationId = testMlApplication.Id,
        ///         Name = mlApplicationName,
        ///         State = mlApplicationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMlApplicationsResult> Invoke(GetMlApplicationsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMlApplicationsResult>("oci:DataScience/getMlApplications:getMlApplications", args ?? new GetMlApplicationsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ml Applications in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Returns a list of MlApplications.
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
        ///     var testMlApplications = Oci.DataScience.GetMlApplications.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = mlApplicationCompartmentIdInSubtree,
        ///         MlApplicationId = testMlApplication.Id,
        ///         Name = mlApplicationName,
        ///         State = mlApplicationState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMlApplicationsResult> Invoke(GetMlApplicationsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMlApplicationsResult>("oci:DataScience/getMlApplications:getMlApplications", args ?? new GetMlApplicationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMlApplicationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// If it is true search must include all results from descendant compartments. Value true is allowed only if compartmentId refers to root compartment.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private List<Inputs.GetMlApplicationsFilterArgs>? _filters;
        public List<Inputs.GetMlApplicationsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetMlApplicationsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique MlApplication identifier
        /// </summary>
        [Input("mlApplicationId")]
        public string? MlApplicationId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to return only resources with lifecycleState matching the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetMlApplicationsArgs()
        {
        }
        public static new GetMlApplicationsArgs Empty => new GetMlApplicationsArgs();
    }

    public sealed class GetMlApplicationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// If it is true search must include all results from descendant compartments. Value true is allowed only if compartmentId refers to root compartment.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetMlApplicationsFilterInputArgs>? _filters;
        public InputList<Inputs.GetMlApplicationsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetMlApplicationsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique MlApplication identifier
        /// </summary>
        [Input("mlApplicationId")]
        public Input<string>? MlApplicationId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire name given.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to return only resources with lifecycleState matching the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetMlApplicationsInvokeArgs()
        {
        }
        public static new GetMlApplicationsInvokeArgs Empty => new GetMlApplicationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetMlApplicationsResult
    {
        /// <summary>
        /// The OCID of the compartment where the MlApplication is created.
        /// </summary>
        public readonly string CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        public readonly ImmutableArray<Outputs.GetMlApplicationsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of ml_application_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMlApplicationsMlApplicationCollectionResult> MlApplicationCollections;
        public readonly string? MlApplicationId;
        /// <summary>
        /// The name of MlApplication. It is unique in a given tenancy.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The current state of the MlApplication.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetMlApplicationsResult(
            string compartmentId,

            bool? compartmentIdInSubtree,

            ImmutableArray<Outputs.GetMlApplicationsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetMlApplicationsMlApplicationCollectionResult> mlApplicationCollections,

            string? mlApplicationId,

            string? name,

            string? state)
        {
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            Filters = filters;
            Id = id;
            MlApplicationCollections = mlApplicationCollections;
            MlApplicationId = mlApplicationId;
            Name = name;
            State = state;
        }
    }
}
