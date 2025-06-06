// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetNamespaces
    {
        /// <summary>
        /// This data source provides the list of Namespaces in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Given a tenancy OCID, this API returns the namespace of the tenancy if it is valid and subscribed to the region.  The
        /// result also indicates if the tenancy is onboarded with Logging Analytics.
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
        ///     var testNamespaces = Oci.LogAnalytics.GetNamespaces.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNamespacesResult> InvokeAsync(GetNamespacesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNamespacesResult>("oci:LogAnalytics/getNamespaces:getNamespaces", args ?? new GetNamespacesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespaces in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Given a tenancy OCID, this API returns the namespace of the tenancy if it is valid and subscribed to the region.  The
        /// result also indicates if the tenancy is onboarded with Logging Analytics.
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
        ///     var testNamespaces = Oci.LogAnalytics.GetNamespaces.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespacesResult> Invoke(GetNamespacesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespacesResult>("oci:LogAnalytics/getNamespaces:getNamespaces", args ?? new GetNamespacesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespaces in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Given a tenancy OCID, this API returns the namespace of the tenancy if it is valid and subscribed to the region.  The
        /// result also indicates if the tenancy is onboarded with Logging Analytics.
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
        ///     var testNamespaces = Oci.LogAnalytics.GetNamespaces.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespacesResult> Invoke(GetNamespacesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespacesResult>("oci:LogAnalytics/getNamespaces:getNamespaces", args ?? new GetNamespacesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNamespacesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetNamespacesFilterArgs>? _filters;
        public List<Inputs.GetNamespacesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNamespacesFilterArgs>());
            set => _filters = value;
        }

        public GetNamespacesArgs()
        {
        }
        public static new GetNamespacesArgs Empty => new GetNamespacesArgs();
    }

    public sealed class GetNamespacesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetNamespacesFilterInputArgs>? _filters;
        public InputList<Inputs.GetNamespacesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNamespacesFilterInputArgs>());
            set => _filters = value;
        }

        public GetNamespacesInvokeArgs()
        {
        }
        public static new GetNamespacesInvokeArgs Empty => new GetNamespacesInvokeArgs();
    }


    [OutputType]
    public sealed class GetNamespacesResult
    {
        /// <summary>
        /// The is the tenancy ID
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetNamespacesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of namespace_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespacesNamespaceCollectionResult> NamespaceCollections;

        [OutputConstructor]
        private GetNamespacesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetNamespacesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetNamespacesNamespaceCollectionResult> namespaceCollections)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            NamespaceCollections = namespaceCollections;
        }
    }
}
