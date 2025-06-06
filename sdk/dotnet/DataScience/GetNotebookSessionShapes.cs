// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetNotebookSessionShapes
    {
        /// <summary>
        /// This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the valid notebook session shapes.
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
        ///     var testNotebookSessionShapes = Oci.DataScience.GetNotebookSessionShapes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNotebookSessionShapesResult> InvokeAsync(GetNotebookSessionShapesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNotebookSessionShapesResult>("oci:DataScience/getNotebookSessionShapes:getNotebookSessionShapes", args ?? new GetNotebookSessionShapesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the valid notebook session shapes.
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
        ///     var testNotebookSessionShapes = Oci.DataScience.GetNotebookSessionShapes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNotebookSessionShapesResult> Invoke(GetNotebookSessionShapesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNotebookSessionShapesResult>("oci:DataScience/getNotebookSessionShapes:getNotebookSessionShapes", args ?? new GetNotebookSessionShapesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Notebook Session Shapes in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// Lists the valid notebook session shapes.
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
        ///     var testNotebookSessionShapes = Oci.DataScience.GetNotebookSessionShapes.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNotebookSessionShapesResult> Invoke(GetNotebookSessionShapesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNotebookSessionShapesResult>("oci:DataScience/getNotebookSessionShapes:getNotebookSessionShapes", args ?? new GetNotebookSessionShapesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNotebookSessionShapesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetNotebookSessionShapesFilterArgs>? _filters;
        public List<Inputs.GetNotebookSessionShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNotebookSessionShapesFilterArgs>());
            set => _filters = value;
        }

        public GetNotebookSessionShapesArgs()
        {
        }
        public static new GetNotebookSessionShapesArgs Empty => new GetNotebookSessionShapesArgs();
    }

    public sealed class GetNotebookSessionShapesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetNotebookSessionShapesFilterInputArgs>? _filters;
        public InputList<Inputs.GetNotebookSessionShapesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNotebookSessionShapesFilterInputArgs>());
            set => _filters = value;
        }

        public GetNotebookSessionShapesInvokeArgs()
        {
        }
        public static new GetNotebookSessionShapesInvokeArgs Empty => new GetNotebookSessionShapesInvokeArgs();
    }


    [OutputType]
    public sealed class GetNotebookSessionShapesResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetNotebookSessionShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of notebook_session_shapes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNotebookSessionShapesNotebookSessionShapeResult> NotebookSessionShapes;

        [OutputConstructor]
        private GetNotebookSessionShapesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetNotebookSessionShapesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetNotebookSessionShapesNotebookSessionShapeResult> notebookSessionShapes)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            NotebookSessionShapes = notebookSessionShapes;
        }
    }
}
