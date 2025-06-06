// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetRepositoryDiff
    {
        /// <summary>
        /// This data source provides details about a specific Repository Diff resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Gets the line-by-line difference between file on different commits. This API will be deprecated on Wed, 29 Mar 2023 01:00:00 GMT as it does not get recognized when filePath has '/'. This will be replaced by "/repositories/{repositoryId}/file/diffs"
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
        ///     var testRepositoryDiff = Oci.DevOps.GetRepositoryDiff.Invoke(new()
        ///     {
        ///         BaseVersion = repositoryDiffBaseVersion,
        ///         FilePath = repositoryDiffFilePath,
        ///         RepositoryId = testRepository.Id,
        ///         TargetVersion = repositoryDiffTargetVersion,
        ///         IsComparisonFromMergeBase = repositoryDiffIsComparisonFromMergeBase,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetRepositoryDiffResult> InvokeAsync(GetRepositoryDiffArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRepositoryDiffResult>("oci:DevOps/getRepositoryDiff:getRepositoryDiff", args ?? new GetRepositoryDiffArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Repository Diff resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Gets the line-by-line difference between file on different commits. This API will be deprecated on Wed, 29 Mar 2023 01:00:00 GMT as it does not get recognized when filePath has '/'. This will be replaced by "/repositories/{repositoryId}/file/diffs"
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
        ///     var testRepositoryDiff = Oci.DevOps.GetRepositoryDiff.Invoke(new()
        ///     {
        ///         BaseVersion = repositoryDiffBaseVersion,
        ///         FilePath = repositoryDiffFilePath,
        ///         RepositoryId = testRepository.Id,
        ///         TargetVersion = repositoryDiffTargetVersion,
        ///         IsComparisonFromMergeBase = repositoryDiffIsComparisonFromMergeBase,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositoryDiffResult> Invoke(GetRepositoryDiffInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositoryDiffResult>("oci:DevOps/getRepositoryDiff:getRepositoryDiff", args ?? new GetRepositoryDiffInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Repository Diff resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Gets the line-by-line difference between file on different commits. This API will be deprecated on Wed, 29 Mar 2023 01:00:00 GMT as it does not get recognized when filePath has '/'. This will be replaced by "/repositories/{repositoryId}/file/diffs"
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
        ///     var testRepositoryDiff = Oci.DevOps.GetRepositoryDiff.Invoke(new()
        ///     {
        ///         BaseVersion = repositoryDiffBaseVersion,
        ///         FilePath = repositoryDiffFilePath,
        ///         RepositoryId = testRepository.Id,
        ///         TargetVersion = repositoryDiffTargetVersion,
        ///         IsComparisonFromMergeBase = repositoryDiffIsComparisonFromMergeBase,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositoryDiffResult> Invoke(GetRepositoryDiffInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositoryDiffResult>("oci:DevOps/getRepositoryDiff:getRepositoryDiff", args ?? new GetRepositoryDiffInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRepositoryDiffArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The branch to compare changes against.
        /// </summary>
        [Input("baseVersion", required: true)]
        public string BaseVersion { get; set; } = null!;

        /// <summary>
        /// Path to a file within a repository.
        /// </summary>
        [Input("filePath", required: true)]
        public string FilePath { get; set; } = null!;

        /// <summary>
        /// Boolean to indicate whether to use merge base or most recent revision.
        /// </summary>
        [Input("isComparisonFromMergeBase")]
        public bool? IsComparisonFromMergeBase { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public string RepositoryId { get; set; } = null!;

        /// <summary>
        /// The branch where changes are coming from.
        /// </summary>
        [Input("targetVersion", required: true)]
        public string TargetVersion { get; set; } = null!;

        public GetRepositoryDiffArgs()
        {
        }
        public static new GetRepositoryDiffArgs Empty => new GetRepositoryDiffArgs();
    }

    public sealed class GetRepositoryDiffInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The branch to compare changes against.
        /// </summary>
        [Input("baseVersion", required: true)]
        public Input<string> BaseVersion { get; set; } = null!;

        /// <summary>
        /// Path to a file within a repository.
        /// </summary>
        [Input("filePath", required: true)]
        public Input<string> FilePath { get; set; } = null!;

        /// <summary>
        /// Boolean to indicate whether to use merge base or most recent revision.
        /// </summary>
        [Input("isComparisonFromMergeBase")]
        public Input<bool>? IsComparisonFromMergeBase { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public Input<string> RepositoryId { get; set; } = null!;

        /// <summary>
        /// The branch where changes are coming from.
        /// </summary>
        [Input("targetVersion", required: true)]
        public Input<string> TargetVersion { get; set; } = null!;

        public GetRepositoryDiffInvokeArgs()
        {
        }
        public static new GetRepositoryDiffInvokeArgs Empty => new GetRepositoryDiffInvokeArgs();
    }


    [OutputType]
    public sealed class GetRepositoryDiffResult
    {
        /// <summary>
        /// Indicates whether the changed file contains conflicts.
        /// </summary>
        public readonly bool AreConflictsInFile;
        public readonly string BaseVersion;
        /// <summary>
        /// List of changed section in the file.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositoryDiffChangeResult> Changes;
        public readonly string FilePath;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether the file is binary.
        /// </summary>
        public readonly bool IsBinary;
        public readonly bool? IsComparisonFromMergeBase;
        /// <summary>
        /// Indicates whether the file is large.
        /// </summary>
        public readonly bool IsLarge;
        /// <summary>
        /// The ID of the changed object on the target version.
        /// </summary>
        public readonly string NewId;
        /// <summary>
        /// The path on the target version to the changed object.
        /// </summary>
        public readonly string NewPath;
        /// <summary>
        /// The ID of the changed object on the base version.
        /// </summary>
        public readonly string OldId;
        /// <summary>
        /// The path on the base version to the changed object.
        /// </summary>
        public readonly string OldPath;
        public readonly string RepositoryId;
        public readonly string TargetVersion;

        [OutputConstructor]
        private GetRepositoryDiffResult(
            bool areConflictsInFile,

            string baseVersion,

            ImmutableArray<Outputs.GetRepositoryDiffChangeResult> changes,

            string filePath,

            string id,

            bool isBinary,

            bool? isComparisonFromMergeBase,

            bool isLarge,

            string newId,

            string newPath,

            string oldId,

            string oldPath,

            string repositoryId,

            string targetVersion)
        {
            AreConflictsInFile = areConflictsInFile;
            BaseVersion = baseVersion;
            Changes = changes;
            FilePath = filePath;
            Id = id;
            IsBinary = isBinary;
            IsComparisonFromMergeBase = isComparisonFromMergeBase;
            IsLarge = isLarge;
            NewId = newId;
            NewPath = newPath;
            OldId = oldId;
            OldPath = oldPath;
            RepositoryId = repositoryId;
            TargetVersion = targetVersion;
        }
    }
}
