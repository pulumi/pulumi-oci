// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetFusionEnvironmentFamilyLimitsAndUsage
    {
        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family Limits And Usage resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets the number of environments (usage) of each type in the fusion environment family, as well as the limit that's allowed to be created based on the group's associated subscriptions.
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
        ///     var testFusionEnvironmentFamilyLimitsAndUsage = Oci.Functions.GetFusionEnvironmentFamilyLimitsAndUsage.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = testFusionEnvironmentFamily.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFusionEnvironmentFamilyLimitsAndUsageResult> InvokeAsync(GetFusionEnvironmentFamilyLimitsAndUsageArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFusionEnvironmentFamilyLimitsAndUsageResult>("oci:Functions/getFusionEnvironmentFamilyLimitsAndUsage:getFusionEnvironmentFamilyLimitsAndUsage", args ?? new GetFusionEnvironmentFamilyLimitsAndUsageArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family Limits And Usage resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets the number of environments (usage) of each type in the fusion environment family, as well as the limit that's allowed to be created based on the group's associated subscriptions.
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
        ///     var testFusionEnvironmentFamilyLimitsAndUsage = Oci.Functions.GetFusionEnvironmentFamilyLimitsAndUsage.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = testFusionEnvironmentFamily.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentFamilyLimitsAndUsageResult> Invoke(GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentFamilyLimitsAndUsageResult>("oci:Functions/getFusionEnvironmentFamilyLimitsAndUsage:getFusionEnvironmentFamilyLimitsAndUsage", args ?? new GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family Limits And Usage resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets the number of environments (usage) of each type in the fusion environment family, as well as the limit that's allowed to be created based on the group's associated subscriptions.
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
        ///     var testFusionEnvironmentFamilyLimitsAndUsage = Oci.Functions.GetFusionEnvironmentFamilyLimitsAndUsage.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = testFusionEnvironmentFamily.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentFamilyLimitsAndUsageResult> Invoke(GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentFamilyLimitsAndUsageResult>("oci:Functions/getFusionEnvironmentFamilyLimitsAndUsage:getFusionEnvironmentFamilyLimitsAndUsage", args ?? new GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFusionEnvironmentFamilyLimitsAndUsageArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the FusionEnvironmentFamily.
        /// </summary>
        [Input("fusionEnvironmentFamilyId", required: true)]
        public string FusionEnvironmentFamilyId { get; set; } = null!;

        public GetFusionEnvironmentFamilyLimitsAndUsageArgs()
        {
        }
        public static new GetFusionEnvironmentFamilyLimitsAndUsageArgs Empty => new GetFusionEnvironmentFamilyLimitsAndUsageArgs();
    }

    public sealed class GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the FusionEnvironmentFamily.
        /// </summary>
        [Input("fusionEnvironmentFamilyId", required: true)]
        public Input<string> FusionEnvironmentFamilyId { get; set; } = null!;

        public GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs()
        {
        }
        public static new GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs Empty => new GetFusionEnvironmentFamilyLimitsAndUsageInvokeArgs();
    }


    [OutputType]
    public sealed class GetFusionEnvironmentFamilyLimitsAndUsageResult
    {
        /// <summary>
        /// The limit and usage for a specific environment type, for example, production, development, or test.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentFamilyLimitsAndUsageDevelopmentLimitAndUsageResult> DevelopmentLimitAndUsages;
        public readonly string FusionEnvironmentFamilyId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The limit and usage for a specific environment type, for example, production, development, or test.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentFamilyLimitsAndUsageProductionLimitAndUsageResult> ProductionLimitAndUsages;
        /// <summary>
        /// The limit and usage for a specific environment type, for example, production, development, or test.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentFamilyLimitsAndUsageTestLimitAndUsageResult> TestLimitAndUsages;

        [OutputConstructor]
        private GetFusionEnvironmentFamilyLimitsAndUsageResult(
            ImmutableArray<Outputs.GetFusionEnvironmentFamilyLimitsAndUsageDevelopmentLimitAndUsageResult> developmentLimitAndUsages,

            string fusionEnvironmentFamilyId,

            string id,

            ImmutableArray<Outputs.GetFusionEnvironmentFamilyLimitsAndUsageProductionLimitAndUsageResult> productionLimitAndUsages,

            ImmutableArray<Outputs.GetFusionEnvironmentFamilyLimitsAndUsageTestLimitAndUsageResult> testLimitAndUsages)
        {
            DevelopmentLimitAndUsages = developmentLimitAndUsages;
            FusionEnvironmentFamilyId = fusionEnvironmentFamilyId;
            Id = id;
            ProductionLimitAndUsages = productionLimitAndUsages;
            TestLimitAndUsages = testLimitAndUsages;
        }
    }
}
