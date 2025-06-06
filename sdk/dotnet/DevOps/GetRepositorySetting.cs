// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps
{
    public static class GetRepositorySetting
    {
        /// <summary>
        /// This data source provides details about a specific Repository Setting resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a repository's settings details.
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
        ///     var testRepositorySetting = Oci.DevOps.GetRepositorySetting.Invoke(new()
        ///     {
        ///         RepositoryId = testRepository.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetRepositorySettingResult> InvokeAsync(GetRepositorySettingArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetRepositorySettingResult>("oci:DevOps/getRepositorySetting:getRepositorySetting", args ?? new GetRepositorySettingArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Repository Setting resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a repository's settings details.
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
        ///     var testRepositorySetting = Oci.DevOps.GetRepositorySetting.Invoke(new()
        ///     {
        ///         RepositoryId = testRepository.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositorySettingResult> Invoke(GetRepositorySettingInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositorySettingResult>("oci:DevOps/getRepositorySetting:getRepositorySetting", args ?? new GetRepositorySettingInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Repository Setting resource in Oracle Cloud Infrastructure Devops service.
        /// 
        /// Retrieves a repository's settings details.
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
        ///     var testRepositorySetting = Oci.DevOps.GetRepositorySetting.Invoke(new()
        ///     {
        ///         RepositoryId = testRepository.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetRepositorySettingResult> Invoke(GetRepositorySettingInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetRepositorySettingResult>("oci:DevOps/getRepositorySetting:getRepositorySetting", args ?? new GetRepositorySettingInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetRepositorySettingArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public string RepositoryId { get; set; } = null!;

        public GetRepositorySettingArgs()
        {
        }
        public static new GetRepositorySettingArgs Empty => new GetRepositorySettingArgs();
    }

    public sealed class GetRepositorySettingInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Unique repository identifier.
        /// </summary>
        [Input("repositoryId", required: true)]
        public Input<string> RepositoryId { get; set; } = null!;

        public GetRepositorySettingInvokeArgs()
        {
        }
        public static new GetRepositorySettingInvokeArgs Empty => new GetRepositorySettingInvokeArgs();
    }


    [OutputType]
    public sealed class GetRepositorySettingResult
    {
        /// <summary>
        /// List of approval rules which must be statisfied before pull requests which match the rules can be merged
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositorySettingApprovalRuleResult> ApprovalRules;
        public readonly string Id;
        /// <summary>
        /// Criteria which must be satisfied to merge a pull request.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositorySettingMergeCheckResult> MergeChecks;
        /// <summary>
        /// Enabled and disabled merge strategies for a project or repository, also contains a default strategy.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetRepositorySettingMergeSettingResult> MergeSettings;
        public readonly string RepositoryId;

        [OutputConstructor]
        private GetRepositorySettingResult(
            ImmutableArray<Outputs.GetRepositorySettingApprovalRuleResult> approvalRules,

            string id,

            ImmutableArray<Outputs.GetRepositorySettingMergeCheckResult> mergeChecks,

            ImmutableArray<Outputs.GetRepositorySettingMergeSettingResult> mergeSettings,

            string repositoryId)
        {
            ApprovalRules = approvalRules;
            Id = id;
            MergeChecks = mergeChecks;
            MergeSettings = mergeSettings;
            RepositoryId = repositoryId;
        }
    }
}
