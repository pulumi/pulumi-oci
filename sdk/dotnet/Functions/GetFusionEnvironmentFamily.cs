// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetFusionEnvironmentFamily
    {
        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Retrieves a fusion environment family identified by its OCID.
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
        ///     var testFusionEnvironmentFamily = Oci.Functions.GetFusionEnvironmentFamily.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = testFusionEnvironmentFamilyOciFusionAppsFusionEnvironmentFamily.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFusionEnvironmentFamilyResult> InvokeAsync(GetFusionEnvironmentFamilyArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFusionEnvironmentFamilyResult>("oci:Functions/getFusionEnvironmentFamily:getFusionEnvironmentFamily", args ?? new GetFusionEnvironmentFamilyArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Retrieves a fusion environment family identified by its OCID.
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
        ///     var testFusionEnvironmentFamily = Oci.Functions.GetFusionEnvironmentFamily.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = testFusionEnvironmentFamilyOciFusionAppsFusionEnvironmentFamily.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentFamilyResult> Invoke(GetFusionEnvironmentFamilyInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentFamilyResult>("oci:Functions/getFusionEnvironmentFamily:getFusionEnvironmentFamily", args ?? new GetFusionEnvironmentFamilyInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Family resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Retrieves a fusion environment family identified by its OCID.
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
        ///     var testFusionEnvironmentFamily = Oci.Functions.GetFusionEnvironmentFamily.Invoke(new()
        ///     {
        ///         FusionEnvironmentFamilyId = testFusionEnvironmentFamilyOciFusionAppsFusionEnvironmentFamily.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentFamilyResult> Invoke(GetFusionEnvironmentFamilyInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentFamilyResult>("oci:Functions/getFusionEnvironmentFamily:getFusionEnvironmentFamily", args ?? new GetFusionEnvironmentFamilyInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFusionEnvironmentFamilyArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the FusionEnvironmentFamily.
        /// </summary>
        [Input("fusionEnvironmentFamilyId", required: true)]
        public string FusionEnvironmentFamilyId { get; set; } = null!;

        public GetFusionEnvironmentFamilyArgs()
        {
        }
        public static new GetFusionEnvironmentFamilyArgs Empty => new GetFusionEnvironmentFamilyArgs();
    }

    public sealed class GetFusionEnvironmentFamilyInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier (OCID) of the FusionEnvironmentFamily.
        /// </summary>
        [Input("fusionEnvironmentFamilyId", required: true)]
        public Input<string> FusionEnvironmentFamilyId { get; set; } = null!;

        public GetFusionEnvironmentFamilyInvokeArgs()
        {
        }
        public static new GetFusionEnvironmentFamilyInvokeArgs Empty => new GetFusionEnvironmentFamilyInvokeArgs();
    }


    [OutputType]
    public sealed class GetFusionEnvironmentFamilyResult
    {
        /// <summary>
        /// The OCID of the compartment where the environment family is located.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A friendly name for the environment family. The name must contain only letters, numbers, dashes, and underscores. Can be changed later.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The policy that specifies the maintenance and upgrade preferences for an environment. For more information about the options, see [Understanding Environment Maintenance](https://docs.cloud.oracle.com/iaas/Content/fusion-applications/plan-environment-family.htm#about-env-maintenance).
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentFamilyFamilyMaintenancePolicyResult> FamilyMaintenancePolicies;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        public readonly string FusionEnvironmentFamilyId;
        /// <summary>
        /// The unique identifier (OCID) of the environment family. Can't be changed after creation.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// When set to True, a subscription update is required for the environment family.
        /// </summary>
        public readonly bool IsSubscriptionUpdateNeeded;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The current state of the FusionEnvironmentFamily.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The list of the IDs of the applications subscriptions that are associated with the environment family.
        /// </summary>
        public readonly ImmutableArray<string> SubscriptionIds;
        /// <summary>
        /// Environment Specific Guid/ System Name
        /// </summary>
        public readonly string SystemName;
        /// <summary>
        /// The time the the FusionEnvironmentFamily was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetFusionEnvironmentFamilyResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            ImmutableArray<Outputs.GetFusionEnvironmentFamilyFamilyMaintenancePolicyResult> familyMaintenancePolicies,

            ImmutableDictionary<string, string> freeformTags,

            string fusionEnvironmentFamilyId,

            string id,

            bool isSubscriptionUpdateNeeded,

            string lifecycleDetails,

            string state,

            ImmutableArray<string> subscriptionIds,

            string systemName,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FamilyMaintenancePolicies = familyMaintenancePolicies;
            FreeformTags = freeformTags;
            FusionEnvironmentFamilyId = fusionEnvironmentFamilyId;
            Id = id;
            IsSubscriptionUpdateNeeded = isSubscriptionUpdateNeeded;
            LifecycleDetails = lifecycleDetails;
            State = state;
            SubscriptionIds = subscriptionIds;
            SystemName = systemName;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
