// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetLogAnalyticsEntityTypes
    {
        /// <summary>
        /// This data source provides the list of Log Analytics Entity Types in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Return a list of log analytics entity types.
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
        ///     var testLogAnalyticsEntityTypes = Oci.LogAnalytics.GetLogAnalyticsEntityTypes.Invoke(new()
        ///     {
        ///         Namespace = logAnalyticsEntityTypeNamespace,
        ///         CloudType = logAnalyticsEntityTypeCloudType,
        ///         Name = logAnalyticsEntityTypeName,
        ///         NameContains = logAnalyticsEntityTypeNameContains,
        ///         State = logAnalyticsEntityTypeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetLogAnalyticsEntityTypesResult> InvokeAsync(GetLogAnalyticsEntityTypesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetLogAnalyticsEntityTypesResult>("oci:LogAnalytics/getLogAnalyticsEntityTypes:getLogAnalyticsEntityTypes", args ?? new GetLogAnalyticsEntityTypesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Log Analytics Entity Types in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Return a list of log analytics entity types.
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
        ///     var testLogAnalyticsEntityTypes = Oci.LogAnalytics.GetLogAnalyticsEntityTypes.Invoke(new()
        ///     {
        ///         Namespace = logAnalyticsEntityTypeNamespace,
        ///         CloudType = logAnalyticsEntityTypeCloudType,
        ///         Name = logAnalyticsEntityTypeName,
        ///         NameContains = logAnalyticsEntityTypeNameContains,
        ///         State = logAnalyticsEntityTypeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetLogAnalyticsEntityTypesResult> Invoke(GetLogAnalyticsEntityTypesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetLogAnalyticsEntityTypesResult>("oci:LogAnalytics/getLogAnalyticsEntityTypes:getLogAnalyticsEntityTypes", args ?? new GetLogAnalyticsEntityTypesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Log Analytics Entity Types in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Return a list of log analytics entity types.
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
        ///     var testLogAnalyticsEntityTypes = Oci.LogAnalytics.GetLogAnalyticsEntityTypes.Invoke(new()
        ///     {
        ///         Namespace = logAnalyticsEntityTypeNamespace,
        ///         CloudType = logAnalyticsEntityTypeCloudType,
        ///         Name = logAnalyticsEntityTypeName,
        ///         NameContains = logAnalyticsEntityTypeNameContains,
        ///         State = logAnalyticsEntityTypeState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetLogAnalyticsEntityTypesResult> Invoke(GetLogAnalyticsEntityTypesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetLogAnalyticsEntityTypesResult>("oci:LogAnalytics/getLogAnalyticsEntityTypes:getLogAnalyticsEntityTypes", args ?? new GetLogAnalyticsEntityTypesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetLogAnalyticsEntityTypesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return CLOUD or NON_CLOUD entity types.
        /// </summary>
        [Input("cloudType")]
        public string? CloudType { get; set; }

        [Input("filters")]
        private List<Inputs.GetLogAnalyticsEntityTypesFilterArgs>? _filters;
        public List<Inputs.GetLogAnalyticsEntityTypesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetLogAnalyticsEntityTypesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only log analytics entity types whose name matches the entire name given. The match is case-insensitive.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to return only log analytics entity types whose name or internalName contains name given. The match is case-insensitive.
        /// </summary>
        [Input("nameContains")]
        public string? NameContains { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// A filter to return only those log analytics entity types with the specified lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetLogAnalyticsEntityTypesArgs()
        {
        }
        public static new GetLogAnalyticsEntityTypesArgs Empty => new GetLogAnalyticsEntityTypesArgs();
    }

    public sealed class GetLogAnalyticsEntityTypesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return CLOUD or NON_CLOUD entity types.
        /// </summary>
        [Input("cloudType")]
        public Input<string>? CloudType { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetLogAnalyticsEntityTypesFilterInputArgs>? _filters;
        public InputList<Inputs.GetLogAnalyticsEntityTypesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetLogAnalyticsEntityTypesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only log analytics entity types whose name matches the entire name given. The match is case-insensitive.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to return only log analytics entity types whose name or internalName contains name given. The match is case-insensitive.
        /// </summary>
        [Input("nameContains")]
        public Input<string>? NameContains { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// A filter to return only those log analytics entity types with the specified lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetLogAnalyticsEntityTypesInvokeArgs()
        {
        }
        public static new GetLogAnalyticsEntityTypesInvokeArgs Empty => new GetLogAnalyticsEntityTypesInvokeArgs();
    }


    [OutputType]
    public sealed class GetLogAnalyticsEntityTypesResult
    {
        /// <summary>
        /// Log analytics entity type group. This can be CLOUD (OCI) or NON_CLOUD otherwise.
        /// </summary>
        public readonly string? CloudType;
        public readonly ImmutableArray<Outputs.GetLogAnalyticsEntityTypesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of log_analytics_entity_type_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollectionResult> LogAnalyticsEntityTypeCollections;
        /// <summary>
        /// Log analytics entity type name.
        /// </summary>
        public readonly string? Name;
        public readonly string? NameContains;
        public readonly string Namespace;
        /// <summary>
        /// The current lifecycle state of the log analytics entity type.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetLogAnalyticsEntityTypesResult(
            string? cloudType,

            ImmutableArray<Outputs.GetLogAnalyticsEntityTypesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetLogAnalyticsEntityTypesLogAnalyticsEntityTypeCollectionResult> logAnalyticsEntityTypeCollections,

            string? name,

            string? nameContains,

            string @namespace,

            string? state)
        {
            CloudType = cloudType;
            Filters = filters;
            Id = id;
            LogAnalyticsEntityTypeCollections = logAnalyticsEntityTypeCollections;
            Name = name;
            NameContains = nameContains;
            Namespace = @namespace;
            State = state;
        }
    }
}
