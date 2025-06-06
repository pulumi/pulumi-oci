// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LogAnalytics
{
    public static class GetNamespaceEffectiveProperties
    {
        /// <summary>
        /// This data source provides the list of Namespace Effective Properties in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of effective properties for the specified resource.
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
        ///     var testNamespaceEffectiveProperties = Oci.LogAnalytics.GetNamespaceEffectiveProperties.Invoke(new()
        ///     {
        ///         Namespace = namespaceEffectivePropertyNamespace,
        ///         AgentId = testAgent.Id,
        ///         EntityId = testLogAnalyticsEntity.Id,
        ///         IsIncludePatterns = namespaceEffectivePropertyIsIncludePatterns,
        ///         Name = namespaceEffectivePropertyName,
        ///         PatternId = testPattern.Id,
        ///         PatternIdLong = namespaceEffectivePropertyPatternIdLong,
        ///         SourceName = namespaceEffectivePropertySourceName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetNamespaceEffectivePropertiesResult> InvokeAsync(GetNamespaceEffectivePropertiesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetNamespaceEffectivePropertiesResult>("oci:LogAnalytics/getNamespaceEffectiveProperties:getNamespaceEffectiveProperties", args ?? new GetNamespaceEffectivePropertiesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Effective Properties in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of effective properties for the specified resource.
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
        ///     var testNamespaceEffectiveProperties = Oci.LogAnalytics.GetNamespaceEffectiveProperties.Invoke(new()
        ///     {
        ///         Namespace = namespaceEffectivePropertyNamespace,
        ///         AgentId = testAgent.Id,
        ///         EntityId = testLogAnalyticsEntity.Id,
        ///         IsIncludePatterns = namespaceEffectivePropertyIsIncludePatterns,
        ///         Name = namespaceEffectivePropertyName,
        ///         PatternId = testPattern.Id,
        ///         PatternIdLong = namespaceEffectivePropertyPatternIdLong,
        ///         SourceName = namespaceEffectivePropertySourceName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespaceEffectivePropertiesResult> Invoke(GetNamespaceEffectivePropertiesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceEffectivePropertiesResult>("oci:LogAnalytics/getNamespaceEffectiveProperties:getNamespaceEffectiveProperties", args ?? new GetNamespaceEffectivePropertiesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Namespace Effective Properties in Oracle Cloud Infrastructure Log Analytics service.
        /// 
        /// Returns a list of effective properties for the specified resource.
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
        ///     var testNamespaceEffectiveProperties = Oci.LogAnalytics.GetNamespaceEffectiveProperties.Invoke(new()
        ///     {
        ///         Namespace = namespaceEffectivePropertyNamespace,
        ///         AgentId = testAgent.Id,
        ///         EntityId = testLogAnalyticsEntity.Id,
        ///         IsIncludePatterns = namespaceEffectivePropertyIsIncludePatterns,
        ///         Name = namespaceEffectivePropertyName,
        ///         PatternId = testPattern.Id,
        ///         PatternIdLong = namespaceEffectivePropertyPatternIdLong,
        ///         SourceName = namespaceEffectivePropertySourceName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetNamespaceEffectivePropertiesResult> Invoke(GetNamespaceEffectivePropertiesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetNamespaceEffectivePropertiesResult>("oci:LogAnalytics/getNamespaceEffectiveProperties:getNamespaceEffectiveProperties", args ?? new GetNamespaceEffectivePropertiesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetNamespaceEffectivePropertiesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The agent ocid.
        /// </summary>
        [Input("agentId")]
        public string? AgentId { get; set; }

        /// <summary>
        /// The entity ocid.
        /// </summary>
        [Input("entityId")]
        public string? EntityId { get; set; }

        [Input("filters")]
        private List<Inputs.GetNamespaceEffectivePropertiesFilterArgs>? _filters;
        public List<Inputs.GetNamespaceEffectivePropertiesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetNamespaceEffectivePropertiesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The include pattern flag.
        /// </summary>
        [Input("isIncludePatterns")]
        public bool? IsIncludePatterns { get; set; }

        /// <summary>
        /// The property name used for filtering.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public string Namespace { get; set; } = null!;

        /// <summary>
        /// The pattern id.
        /// </summary>
        [Input("patternId")]
        public int? PatternId { get; set; }

        /// <summary>
        /// The pattern id (long).
        /// </summary>
        [Input("patternIdLong")]
        public string? PatternIdLong { get; set; }

        /// <summary>
        /// The source name.
        /// </summary>
        [Input("sourceName")]
        public string? SourceName { get; set; }

        public GetNamespaceEffectivePropertiesArgs()
        {
        }
        public static new GetNamespaceEffectivePropertiesArgs Empty => new GetNamespaceEffectivePropertiesArgs();
    }

    public sealed class GetNamespaceEffectivePropertiesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The agent ocid.
        /// </summary>
        [Input("agentId")]
        public Input<string>? AgentId { get; set; }

        /// <summary>
        /// The entity ocid.
        /// </summary>
        [Input("entityId")]
        public Input<string>? EntityId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetNamespaceEffectivePropertiesFilterInputArgs>? _filters;
        public InputList<Inputs.GetNamespaceEffectivePropertiesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetNamespaceEffectivePropertiesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The include pattern flag.
        /// </summary>
        [Input("isIncludePatterns")]
        public Input<bool>? IsIncludePatterns { get; set; }

        /// <summary>
        /// The property name used for filtering.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// The Logging Analytics namespace used for the request.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// The pattern id.
        /// </summary>
        [Input("patternId")]
        public Input<int>? PatternId { get; set; }

        /// <summary>
        /// The pattern id (long).
        /// </summary>
        [Input("patternIdLong")]
        public Input<string>? PatternIdLong { get; set; }

        /// <summary>
        /// The source name.
        /// </summary>
        [Input("sourceName")]
        public Input<string>? SourceName { get; set; }

        public GetNamespaceEffectivePropertiesInvokeArgs()
        {
        }
        public static new GetNamespaceEffectivePropertiesInvokeArgs Empty => new GetNamespaceEffectivePropertiesInvokeArgs();
    }


    [OutputType]
    public sealed class GetNamespaceEffectivePropertiesResult
    {
        public readonly string? AgentId;
        /// <summary>
        /// The list of effective_property_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetNamespaceEffectivePropertiesEffectivePropertyCollectionResult> EffectivePropertyCollections;
        public readonly string? EntityId;
        public readonly ImmutableArray<Outputs.GetNamespaceEffectivePropertiesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsIncludePatterns;
        /// <summary>
        /// The property name.
        /// </summary>
        public readonly string? Name;
        public readonly string Namespace;
        public readonly int? PatternId;
        public readonly string? PatternIdLong;
        public readonly string? SourceName;

        [OutputConstructor]
        private GetNamespaceEffectivePropertiesResult(
            string? agentId,

            ImmutableArray<Outputs.GetNamespaceEffectivePropertiesEffectivePropertyCollectionResult> effectivePropertyCollections,

            string? entityId,

            ImmutableArray<Outputs.GetNamespaceEffectivePropertiesFilterResult> filters,

            string id,

            bool? isIncludePatterns,

            string? name,

            string @namespace,

            int? patternId,

            string? patternIdLong,

            string? sourceName)
        {
            AgentId = agentId;
            EffectivePropertyCollections = effectivePropertyCollections;
            EntityId = entityId;
            Filters = filters;
            Id = id;
            IsIncludePatterns = isIncludePatterns;
            Name = name;
            Namespace = @namespace;
            PatternId = patternId;
            PatternIdLong = patternIdLong;
            SourceName = sourceName;
        }
    }
}
