// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetFusionEnvironmentFamilySubscriptionDetail
    {
        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family Subscription Detail resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets the subscription details of an fusion environment family.
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
        ///     var testFusionEnvironmentFamilySubscriptionDetail = Oci.Functions.GetFusionEnvironmentFamilySubscriptionDetail.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = oci_fusion_apps_fusion_environment_family.Test_fusion_environment_family.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFusionEnvironmentFamilySubscriptionDetailResult> InvokeAsync(GetFusionEnvironmentFamilySubscriptionDetailArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFusionEnvironmentFamilySubscriptionDetailResult>("oci:Functions/getFusionEnvironmentFamilySubscriptionDetail:getFusionEnvironmentFamilySubscriptionDetail", args ?? new GetFusionEnvironmentFamilySubscriptionDetailArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family Subscription Detail resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets the subscription details of an fusion environment family.
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
        ///     var testFusionEnvironmentFamilySubscriptionDetail = Oci.Functions.GetFusionEnvironmentFamilySubscriptionDetail.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = oci_fusion_apps_fusion_environment_family.Test_fusion_environment_family.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFusionEnvironmentFamilySubscriptionDetailResult> Invoke(GetFusionEnvironmentFamilySubscriptionDetailInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentFamilySubscriptionDetailResult>("oci:Functions/getFusionEnvironmentFamilySubscriptionDetail:getFusionEnvironmentFamilySubscriptionDetail", args ?? new GetFusionEnvironmentFamilySubscriptionDetailInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFusionEnvironmentFamilySubscriptionDetailArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the FusionEnvironmentFamily.
        /// </summary>
        [Input("fusionEnvironmentFamilyId", required: true)]
        public string FusionEnvironmentFamilyId { get; set; } = null!;

        public GetFusionEnvironmentFamilySubscriptionDetailArgs()
        {
        }
        public static new GetFusionEnvironmentFamilySubscriptionDetailArgs Empty => new GetFusionEnvironmentFamilySubscriptionDetailArgs();
    }

    public sealed class GetFusionEnvironmentFamilySubscriptionDetailInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the FusionEnvironmentFamily.
        /// </summary>
        [Input("fusionEnvironmentFamilyId", required: true)]
        public Input<string> FusionEnvironmentFamilyId { get; set; } = null!;

        public GetFusionEnvironmentFamilySubscriptionDetailInvokeArgs()
        {
        }
        public static new GetFusionEnvironmentFamilySubscriptionDetailInvokeArgs Empty => new GetFusionEnvironmentFamilySubscriptionDetailInvokeArgs();
    }


    [OutputType]
    public sealed class GetFusionEnvironmentFamilySubscriptionDetailResult
    {
        public readonly string FusionEnvironmentFamilyId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// List of subscriptions.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentFamilySubscriptionDetailSubscriptionResult> Subscriptions;

        [OutputConstructor]
        private GetFusionEnvironmentFamilySubscriptionDetailResult(
            string fusionEnvironmentFamilyId,

            string id,

            ImmutableArray<Outputs.GetFusionEnvironmentFamilySubscriptionDetailSubscriptionResult> subscriptions)
        {
            FusionEnvironmentFamilyId = fusionEnvironmentFamilyId;
            Id = id;
            Subscriptions = subscriptions;
        }
    }
}