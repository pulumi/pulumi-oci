// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmConfig
{
    public static class GetConfig
    {
        /// <summary>
        /// This data source provides details about a specific Config resource in Oracle Cloud Infrastructure Apm Config service.
        /// 
        /// Get the configuration of the item identified by the OCID.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testConfig = Output.Create(Oci.ApmConfig.GetConfig.InvokeAsync(new Oci.ApmConfig.GetConfigArgs
        ///         {
        ///             ApmDomainId = oci_apm_apm_domain.Test_apm_domain.Id,
        ///             ConfigId = oci_apm_config_config.Test_config.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetConfigResult> InvokeAsync(GetConfigArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetConfigResult>("oci:ApmConfig/getConfig:getConfig", args ?? new GetConfigArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Config resource in Oracle Cloud Infrastructure Apm Config service.
        /// 
        /// Get the configuration of the item identified by the OCID.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testConfig = Output.Create(Oci.ApmConfig.GetConfig.InvokeAsync(new Oci.ApmConfig.GetConfigArgs
        ///         {
        ///             ApmDomainId = oci_apm_apm_domain.Test_apm_domain.Id,
        ///             ConfigId = oci_apm_config_config.Test_config.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetConfigResult> Invoke(GetConfigInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetConfigResult>("oci:ApmConfig/getConfig:getConfig", args ?? new GetConfigInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetConfigArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM Domain Id the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public string ApmDomainId { get; set; } = null!;

        /// <summary>
        /// The OCID of the ConfiguredItem.
        /// </summary>
        [Input("configId", required: true)]
        public string ConfigId { get; set; } = null!;

        public GetConfigArgs()
        {
        }
    }

    public sealed class GetConfigInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM Domain Id the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public Input<string> ApmDomainId { get; set; } = null!;

        /// <summary>
        /// The OCID of the ConfiguredItem.
        /// </summary>
        [Input("configId", required: true)]
        public Input<string> ConfigId { get; set; } = null!;

        public GetConfigInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetConfigResult
    {
        public readonly string ApmDomainId;
        public readonly string ConfigId;
        /// <summary>
        /// The type of configuration item
        /// </summary>
        public readonly string ConfigType;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// A description of the metric
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A list of dimensions for this metric
        /// </summary>
        public readonly ImmutableArray<Outputs.GetConfigDimensionResult> Dimensions;
        /// <summary>
        /// A user-friendly name that provides a short description this rule.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Span Filter. The filterId is mandatory for the creation of MetricGroups. A filterId will be generated when a Span Filter is created.
        /// </summary>
        public readonly string FilterId;
        /// <summary>
        /// The string that defines the Span Filter expression.
        /// </summary>
        public readonly string FilterText;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the configuration item. An OCID will be generated when the item is created.
        /// </summary>
        public readonly string Id;
        public readonly ImmutableArray<Outputs.GetConfigMetricResult> Metrics;
        /// <summary>
        /// The namespace to write the metrics to
        /// </summary>
        public readonly string Namespace;
        public readonly string OpcDryRun;
        public readonly ImmutableArray<Outputs.GetConfigRuleResult> Rules;
        /// <summary>
        /// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetConfigResult(
            string apmDomainId,

            string configId,

            string configType,

            ImmutableDictionary<string, object> definedTags,

            string description,

            ImmutableArray<Outputs.GetConfigDimensionResult> dimensions,

            string displayName,

            string filterId,

            string filterText,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            ImmutableArray<Outputs.GetConfigMetricResult> metrics,

            string @namespace,

            string opcDryRun,

            ImmutableArray<Outputs.GetConfigRuleResult> rules,

            string timeCreated,

            string timeUpdated)
        {
            ApmDomainId = apmDomainId;
            ConfigId = configId;
            ConfigType = configType;
            DefinedTags = definedTags;
            Description = description;
            Dimensions = dimensions;
            DisplayName = displayName;
            FilterId = filterId;
            FilterText = filterText;
            FreeformTags = freeformTags;
            Id = id;
            Metrics = metrics;
            Namespace = @namespace;
            OpcDryRun = opcDryRun;
            Rules = rules;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
