// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opensearch
{
    public static class GetOpensearchVersions
    {
        /// <summary>
        /// This data source provides the list of Opensearch Versions in Oracle Cloud Infrastructure Opensearch service.
        /// 
        /// Lists the supported Opensearch versions
        /// 
        /// ## Prerequisites
        /// 
        /// The below policies must be created in compartment before creating OpensearchCluster
        /// 
        /// ##### {Compartment-Name} - Name of  your compartment
        /// ```
        /// Allow service opensearch to manage vnics in compartment {Compartment-Name}
        /// Allow service opensearch to use subnets in compartment {Compartment-Name}
        /// Allow service opensearch to use network-security-groups in compartment {Compartment-Name}
        /// Allow service opensearch to manage vcns in compartment {Compartment-Name}
        /// ```
        /// 
        /// For latest documentation on OpenSearch use please refer to https://docs.oracle.com/en-us/iaas/Content/search-opensearch/home.htm  
        /// Required permissions: https://docs.oracle.com/en-us/iaas/Content/search-opensearch/Concepts/ocisearchpermissions.htm
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
        ///     var testOpensearchVersions = Oci.Opensearch.GetOpensearchVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetOpensearchVersionsResult> InvokeAsync(GetOpensearchVersionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetOpensearchVersionsResult>("oci:Opensearch/getOpensearchVersions:getOpensearchVersions", args ?? new GetOpensearchVersionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Opensearch Versions in Oracle Cloud Infrastructure Opensearch service.
        /// 
        /// Lists the supported Opensearch versions
        /// 
        /// ## Prerequisites
        /// 
        /// The below policies must be created in compartment before creating OpensearchCluster
        /// 
        /// ##### {Compartment-Name} - Name of  your compartment
        /// ```
        /// Allow service opensearch to manage vnics in compartment {Compartment-Name}
        /// Allow service opensearch to use subnets in compartment {Compartment-Name}
        /// Allow service opensearch to use network-security-groups in compartment {Compartment-Name}
        /// Allow service opensearch to manage vcns in compartment {Compartment-Name}
        /// ```
        /// 
        /// For latest documentation on OpenSearch use please refer to https://docs.oracle.com/en-us/iaas/Content/search-opensearch/home.htm  
        /// Required permissions: https://docs.oracle.com/en-us/iaas/Content/search-opensearch/Concepts/ocisearchpermissions.htm
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
        ///     var testOpensearchVersions = Oci.Opensearch.GetOpensearchVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOpensearchVersionsResult> Invoke(GetOpensearchVersionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetOpensearchVersionsResult>("oci:Opensearch/getOpensearchVersions:getOpensearchVersions", args ?? new GetOpensearchVersionsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Opensearch Versions in Oracle Cloud Infrastructure Opensearch service.
        /// 
        /// Lists the supported Opensearch versions
        /// 
        /// ## Prerequisites
        /// 
        /// The below policies must be created in compartment before creating OpensearchCluster
        /// 
        /// ##### {Compartment-Name} - Name of  your compartment
        /// ```
        /// Allow service opensearch to manage vnics in compartment {Compartment-Name}
        /// Allow service opensearch to use subnets in compartment {Compartment-Name}
        /// Allow service opensearch to use network-security-groups in compartment {Compartment-Name}
        /// Allow service opensearch to manage vcns in compartment {Compartment-Name}
        /// ```
        /// 
        /// For latest documentation on OpenSearch use please refer to https://docs.oracle.com/en-us/iaas/Content/search-opensearch/home.htm  
        /// Required permissions: https://docs.oracle.com/en-us/iaas/Content/search-opensearch/Concepts/ocisearchpermissions.htm
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
        ///     var testOpensearchVersions = Oci.Opensearch.GetOpensearchVersions.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetOpensearchVersionsResult> Invoke(GetOpensearchVersionsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetOpensearchVersionsResult>("oci:Opensearch/getOpensearchVersions:getOpensearchVersions", args ?? new GetOpensearchVersionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOpensearchVersionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetOpensearchVersionsFilterArgs>? _filters;
        public List<Inputs.GetOpensearchVersionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOpensearchVersionsFilterArgs>());
            set => _filters = value;
        }

        public GetOpensearchVersionsArgs()
        {
        }
        public static new GetOpensearchVersionsArgs Empty => new GetOpensearchVersionsArgs();
    }

    public sealed class GetOpensearchVersionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetOpensearchVersionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetOpensearchVersionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOpensearchVersionsFilterInputArgs>());
            set => _filters = value;
        }

        public GetOpensearchVersionsInvokeArgs()
        {
        }
        public static new GetOpensearchVersionsInvokeArgs Empty => new GetOpensearchVersionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetOpensearchVersionsResult
    {
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetOpensearchVersionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of opensearch_versions_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOpensearchVersionsOpensearchVersionsCollectionResult> OpensearchVersionsCollections;

        [OutputConstructor]
        private GetOpensearchVersionsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetOpensearchVersionsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetOpensearchVersionsOpensearchVersionsCollectionResult> opensearchVersionsCollections)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            OpensearchVersionsCollections = opensearchVersionsCollections;
        }
    }
}
