// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Adm
{
    public static class GetKnowledgebases
    {
        /// <summary>
        /// This data source provides the list of Knowledge Bases in Oracle Cloud Infrastructure ADM service.
        /// 
        /// Returns a list of KnowledgeBases based on the specified query parameters.
        /// At least id or compartmentId query parameter must be provided.
        /// 
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
        ///     var testKnowledgeBases = Oci.Adm.GetKnowledgebases.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Knowledge_base_display_name,
        ///         Id = @var.Knowledge_base_id,
        ///         State = @var.Knowledge_base_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetKnowledgebasesResult> InvokeAsync(GetKnowledgebasesArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetKnowledgebasesResult>("oci:Adm/getKnowledgebases:getKnowledgebases", args ?? new GetKnowledgebasesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Knowledge Bases in Oracle Cloud Infrastructure ADM service.
        /// 
        /// Returns a list of KnowledgeBases based on the specified query parameters.
        /// At least id or compartmentId query parameter must be provided.
        /// 
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
        ///     var testKnowledgeBases = Oci.Adm.GetKnowledgebases.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Knowledge_base_display_name,
        ///         Id = @var.Knowledge_base_id,
        ///         State = @var.Knowledge_base_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetKnowledgebasesResult> Invoke(GetKnowledgebasesInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetKnowledgebasesResult>("oci:Adm/getKnowledgebases:getKnowledgebases", args ?? new GetKnowledgebasesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetKnowledgebasesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that belong to the specified compartment identifier.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetKnowledgebasesFilterArgs>? _filters;
        public List<Inputs.GetKnowledgebasesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetKnowledgebasesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the specified identifier.
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// A filter to return only Knowledge Bases that match the specified lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetKnowledgebasesArgs()
        {
        }
        public static new GetKnowledgebasesArgs Empty => new GetKnowledgebasesArgs();
    }

    public sealed class GetKnowledgebasesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that belong to the specified compartment identifier.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetKnowledgebasesFilterInputArgs>? _filters;
        public InputList<Inputs.GetKnowledgebasesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetKnowledgebasesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the specified identifier.
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// A filter to return only Knowledge Bases that match the specified lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetKnowledgebasesInvokeArgs()
        {
        }
        public static new GetKnowledgebasesInvokeArgs Empty => new GetKnowledgebasesInvokeArgs();
    }


    [OutputType]
    public sealed class GetKnowledgebasesResult
    {
        /// <summary>
        /// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Knowledge Base's compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// The name of the Knowledge Base.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetKnowledgebasesFilterResult> Filters;
        /// <summary>
        /// The Oracle Cloud Identifier ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)) of the Knowledge Base.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of knowledge_base_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetKnowledgebasesKnowledgeBaseCollectionResult> KnowledgeBaseCollections;
        /// <summary>
        /// The current lifecycle state of the Knowledge Base.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetKnowledgebasesResult(
            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetKnowledgebasesFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetKnowledgebasesKnowledgeBaseCollectionResult> knowledgeBaseCollections,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            KnowledgeBaseCollections = knowledgeBaseCollections;
            State = state;
        }
    }
}