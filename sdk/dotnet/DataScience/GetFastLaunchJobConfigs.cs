// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataScience
{
    public static class GetFastLaunchJobConfigs
    {
        /// <summary>
        /// This data source provides the list of Fast Launch Job Configs in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// List fast launch capable job configs in the specified compartment.
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
        ///     var testFastLaunchJobConfigs = Oci.DataScience.GetFastLaunchJobConfigs.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFastLaunchJobConfigsResult> InvokeAsync(GetFastLaunchJobConfigsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetFastLaunchJobConfigsResult>("oci:DataScience/getFastLaunchJobConfigs:getFastLaunchJobConfigs", args ?? new GetFastLaunchJobConfigsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fast Launch Job Configs in Oracle Cloud Infrastructure Data Science service.
        /// 
        /// List fast launch capable job configs in the specified compartment.
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
        ///     var testFastLaunchJobConfigs = Oci.DataScience.GetFastLaunchJobConfigs.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFastLaunchJobConfigsResult> Invoke(GetFastLaunchJobConfigsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetFastLaunchJobConfigsResult>("oci:DataScience/getFastLaunchJobConfigs:getFastLaunchJobConfigs", args ?? new GetFastLaunchJobConfigsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFastLaunchJobConfigsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetFastLaunchJobConfigsFilterArgs>? _filters;
        public List<Inputs.GetFastLaunchJobConfigsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFastLaunchJobConfigsFilterArgs>());
            set => _filters = value;
        }

        public GetFastLaunchJobConfigsArgs()
        {
        }
        public static new GetFastLaunchJobConfigsArgs Empty => new GetFastLaunchJobConfigsArgs();
    }

    public sealed class GetFastLaunchJobConfigsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// &lt;b&gt;Filter&lt;/b&gt; results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetFastLaunchJobConfigsFilterInputArgs>? _filters;
        public InputList<Inputs.GetFastLaunchJobConfigsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetFastLaunchJobConfigsFilterInputArgs>());
            set => _filters = value;
        }

        public GetFastLaunchJobConfigsInvokeArgs()
        {
        }
        public static new GetFastLaunchJobConfigsInvokeArgs Empty => new GetFastLaunchJobConfigsInvokeArgs();
    }


    [OutputType]
    public sealed class GetFastLaunchJobConfigsResult
    {
        public readonly string CompartmentId;
        /// <summary>
        /// The list of fast_launch_job_configs.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFastLaunchJobConfigsFastLaunchJobConfigResult> FastLaunchJobConfigs;
        public readonly ImmutableArray<Outputs.GetFastLaunchJobConfigsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetFastLaunchJobConfigsResult(
            string compartmentId,

            ImmutableArray<Outputs.GetFastLaunchJobConfigsFastLaunchJobConfigResult> fastLaunchJobConfigs,

            ImmutableArray<Outputs.GetFastLaunchJobConfigsFilterResult> filters,

            string id)
        {
            CompartmentId = compartmentId;
            FastLaunchJobConfigs = fastLaunchJobConfigs;
            Filters = filters;
            Id = id;
        }
    }
}