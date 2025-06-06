// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetRepositoryDiffs
    {
        /// <summary>
        /// This data source provides the list of Repository Diffs in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Compares two revisions and lists the differences. Supports comparison between two references or commits.
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
        ///     var testRepositoryDiffs = Oci.DevOps.GetRepositoryDiffs.Invoke(new()
        ///     {
        ///         BaseVersion = repositoryDiffBaseVersion,
        ///         RepositoryId = testRepository.Id,
        ///         TargetVersion = repositoryDiffTargetVersion,
        ///         IsComparisonFromMergeBase = repositoryDiffIsComparisonFromMergeBase,
        ///         TargetRepositoryId = testRepository.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetRepositoryDiffsResult> InvokeAsync(GetRepositoryDiffsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRepositoryDiffsResult>("oci:DevOps/getRepositoryDiffs:getRepositoryDiffs", args ?? new GetRepositoryDiffsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Repository Diffs in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Compares two revisions and lists the differences. Supports comparison between two references or commits.
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
        ///     var testRepositoryDiffs = Oci.DevOps.GetRepositoryDiffs.Invoke(new()
        ///     {
        ///         BaseVersion = repositoryDiffBaseVersion,
        ///         RepositoryId = testRepository.Id,
        ///         TargetVersion = repositoryDiffTargetVersion,
        ///         IsComparisonFromMergeBase = repositoryDiffIsComparisonFromMergeBase,
        ///         TargetRepositoryId = testRepository.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositoryDiffsResult> Invoke(GetRepositoryDiffsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositoryDiffsResult>("oci:DevOps/getRepositoryDiffs:getRepositoryDiffs", args ?? new GetRepositoryDiffsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Repository Diffs in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Compares two revisions and lists the differences. Supports comparison between two references or commits.
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
        ///     var testRepositoryDiffs = Oci.DevOps.GetRepositoryDiffs.Invoke(new()
        ///     {
        ///         BaseVersion = repositoryDiffBaseVersion,
        ///         RepositoryId = testRepository.Id,
        ///         TargetVersion = repositoryDiffTargetVersion,
        ///         IsComparisonFromMergeBase = repositoryDiffIsComparisonFromMergeBase,
        ///         TargetRepositoryId = testRepository.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositoryDiffsResult> Invoke(GetRepositoryDiffsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositoryDiffsResult>("oci:DevOps/getRepositoryDiffs:getRepositoryDiffs", args ?? new GetRepositoryDiffsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRepositoryDiffsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The commit or reference name to compare changes against.
        /// </summary>
        [Input("baseVersion", required: true)]
        public string BaseVersion { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetRepositoryDiffsFilterArgs>? _filters;
        public List<Inputs.GetRepositoryDiffsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRepositoryDiffsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Boolean value to indicate whether to use merge base or most recent revision.
        /// </summary>
        [Input("isComparisonFromMergeBase")]
        public bool? IsComparisonFromMergeBase { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public string RepositoryId { get; set; } = null!;

        /// <summary>
        /// The target repository identifier
        /// </summary>
        [Input("targetRepositoryId")]
        public string? TargetRepositoryId { get; set; }

        /// <summary>
        /// The commit or reference name where changes are coming from.
        /// </summary>
        [Input("targetVersion", required: true)]
        public string TargetVersion { get; set; } = null!;

        public GetRepositoryDiffsArgs()
        {
        }
        public static new GetRepositoryDiffsArgs Empty => new GetRepositoryDiffsArgs();
    }

    public sealed class GetRepositoryDiffsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The commit or reference name to compare changes against.
        /// </summary>
        [Input("baseVersion", required: true)]
        public Input<string> BaseVersion { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetRepositoryDiffsFilterInputArgs>? _filters;
        public InputList<Inputs.GetRepositoryDiffsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetRepositoryDiffsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Boolean value to indicate whether to use merge base or most recent revision.
        /// </summary>
        [Input("isComparisonFromMergeBase")]
        public Input<bool>? IsComparisonFromMergeBase { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public Input<string> RepositoryId { get; set; } = null!;

        /// <summary>
        /// The target repository identifier
        /// </summary>
        [Input("targetRepositoryId")]
        public Input<string>? TargetRepositoryId { get; set; }

        /// <summary>
        /// The commit or reference name where changes are coming from.
        /// </summary>
        [Input("targetVersion", required: true)]
        public Input<string> TargetVersion { get; set; } = null!;

        public GetRepositoryDiffsInvokeArgs()
        {
        }
        public static new GetRepositoryDiffsInvokeArgs Empty => new GetRepositoryDiffsInvokeArgs();
    }


    [OutputType]
    public sealed class GetRepositoryDiffsResult
    {
        public readonly string BaseVersion;
        /// <summary>
        /// The list of diff_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositoryDiffsDiffCollectionResult> DiffCollections;
        public readonly ImmutableArray<Outputs.GetRepositoryDiffsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly bool? IsComparisonFromMergeBase;
        public readonly string RepositoryId;
        public readonly string? TargetRepositoryId;
        public readonly string TargetVersion;

        [OutputConstructor]
        private GetRepositoryDiffsResult(
            string baseVersion,

            ImmutableArray<Outputs.GetRepositoryDiffsDiffCollectionResult> diffCollections,

            ImmutableArray<Outputs.GetRepositoryDiffsFilterResult> filters,

            string id,

            bool? isComparisonFromMergeBase,

            string repositoryId,

            string? targetRepositoryId,

            string targetVersion)
        {
            BaseVersion = baseVersion;
            DiffCollections = diffCollections;
            Filters = filters;
            Id = id;
            IsComparisonFromMergeBase = isComparisonFromMergeBase;
            RepositoryId = repositoryId;
            TargetRepositoryId = targetRepositoryId;
            TargetVersion = targetVersion;
        }
    }
}
