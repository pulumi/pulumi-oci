// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetRepositoryProtectedBranches
    {
        /// <summary>
        /// This data source provides the list of Repository Protected Branches in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of Protected Branches.
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
        ///     var testRepositoryProtectedBranches = Oci.DevOps.GetRepositoryProtectedBranches.Invoke(new()
        ///     {
        ///         RepositoryId = testRepository.Id,
        ///         Name = repositoryProtectedBranchName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetRepositoryProtectedBranchesResult> InvokeAsync(GetRepositoryProtectedBranchesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRepositoryProtectedBranchesResult>("oci:DevOps/getRepositoryProtectedBranches:getRepositoryProtectedBranches", args ?? new GetRepositoryProtectedBranchesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Repository Protected Branches in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of Protected Branches.
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
        ///     var testRepositoryProtectedBranches = Oci.DevOps.GetRepositoryProtectedBranches.Invoke(new()
        ///     {
        ///         RepositoryId = testRepository.Id,
        ///         Name = repositoryProtectedBranchName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositoryProtectedBranchesResult> Invoke(GetRepositoryProtectedBranchesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositoryProtectedBranchesResult>("oci:DevOps/getRepositoryProtectedBranches:getRepositoryProtectedBranches", args ?? new GetRepositoryProtectedBranchesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Repository Protected Branches in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Returns a list of Protected Branches.
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
        ///     var testRepositoryProtectedBranches = Oci.DevOps.GetRepositoryProtectedBranches.Invoke(new()
        ///     {
        ///         RepositoryId = testRepository.Id,
        ///         Name = repositoryProtectedBranchName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositoryProtectedBranchesResult> Invoke(GetRepositoryProtectedBranchesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositoryProtectedBranchesResult>("oci:DevOps/getRepositoryProtectedBranches:getRepositoryProtectedBranches", args ?? new GetRepositoryProtectedBranchesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRepositoryProtectedBranchesArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetRepositoryProtectedBranchesFilterArgs>? _filters;
        public List<Inputs.GetRepositoryProtectedBranchesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetRepositoryProtectedBranchesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given branch name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public string RepositoryId { get; set; } = null!;

        public GetRepositoryProtectedBranchesArgs()
        {
        }
        public static new GetRepositoryProtectedBranchesArgs Empty => new GetRepositoryProtectedBranchesArgs();
    }

    public sealed class GetRepositoryProtectedBranchesInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetRepositoryProtectedBranchesFilterInputArgs>? _filters;
        public InputList<Inputs.GetRepositoryProtectedBranchesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetRepositoryProtectedBranchesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given branch name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public Input<string> RepositoryId { get; set; } = null!;

        public GetRepositoryProtectedBranchesInvokeArgs()
        {
        }
        public static new GetRepositoryProtectedBranchesInvokeArgs Empty => new GetRepositoryProtectedBranchesInvokeArgs();
    }


    [OutputType]
    public sealed class GetRepositoryProtectedBranchesResult
    {
        public readonly ImmutableArray<Outputs.GetRepositoryProtectedBranchesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? Name;
        /// <summary>
        /// The list of protected_branch_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositoryProtectedBranchesProtectedBranchCollectionResult> ProtectedBranchCollections;
        public readonly string RepositoryId;

        [OutputConstructor]
        private GetRepositoryProtectedBranchesResult(
            ImmutableArray<Outputs.GetRepositoryProtectedBranchesFilterResult> filters,

            string id,

            string? name,

            ImmutableArray<Outputs.GetRepositoryProtectedBranchesProtectedBranchCollectionResult> protectedBranchCollections,

            string repositoryId)
        {
            Filters = filters;
            Id = id;
            Name = name;
            ProtectedBranchCollections = protectedBranchCollections;
            RepositoryId = repositoryId;
        }
    }
}
