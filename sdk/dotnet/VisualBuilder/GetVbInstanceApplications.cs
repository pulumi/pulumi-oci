// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.VisualBuilder
{
    public static class GetVbInstanceApplications
    {
        /// <summary>
        /// This data source provides the list of published and staged applications of a Visual Builder Instance in Oracle Cloud Infrastructure Visual Builder service.
        /// 
        /// Returns a list of published and staged applications of a Visual Builder instance.
        /// 
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
        ///     var testVbInstanceApplications = Oci.VisualBuilder.GetVbInstanceApplications.Invoke(new()
        ///     {
        ///         VbInstanceId = oci_visual_builder_vb_instance.Test_vb_instance.Id,
        ///         IdcsOpenId = "idcs_open_id_value",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetVbInstanceApplicationsResult> InvokeAsync(GetVbInstanceApplicationsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetVbInstanceApplicationsResult>("oci:VisualBuilder/getVbInstanceApplications:getVbInstanceApplications", args ?? new GetVbInstanceApplicationsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of published and staged applications of a Visual Builder Instance in Oracle Cloud Infrastructure Visual Builder service.
        /// 
        /// Returns a list of published and staged applications of a Visual Builder instance.
        /// 
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
        ///     var testVbInstanceApplications = Oci.VisualBuilder.GetVbInstanceApplications.Invoke(new()
        ///     {
        ///         VbInstanceId = oci_visual_builder_vb_instance.Test_vb_instance.Id,
        ///         IdcsOpenId = "idcs_open_id_value",
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetVbInstanceApplicationsResult> Invoke(GetVbInstanceApplicationsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetVbInstanceApplicationsResult>("oci:VisualBuilder/getVbInstanceApplications:getVbInstanceApplications", args ?? new GetVbInstanceApplicationsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVbInstanceApplicationsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Encrypted IDCS Open ID token which allows access to Visual Builder REST apis
        /// </summary>
        [Input("idcsOpenId")]
        public string? IdcsOpenId { get; set; }

        /// <summary>
        /// Unique Vb Instance identifier.
        /// </summary>
        [Input("vbInstanceId", required: true)]
        public string VbInstanceId { get; set; } = null!;

        public GetVbInstanceApplicationsArgs()
        {
        }
        public static new GetVbInstanceApplicationsArgs Empty => new GetVbInstanceApplicationsArgs();
    }

    public sealed class GetVbInstanceApplicationsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Encrypted IDCS Open ID token which allows access to Visual Builder REST apis
        /// </summary>
        [Input("idcsOpenId")]
        public Input<string>? IdcsOpenId { get; set; }

        /// <summary>
        /// Unique Vb Instance identifier.
        /// </summary>
        [Input("vbInstanceId", required: true)]
        public Input<string> VbInstanceId { get; set; } = null!;

        public GetVbInstanceApplicationsInvokeArgs()
        {
        }
        public static new GetVbInstanceApplicationsInvokeArgs Empty => new GetVbInstanceApplicationsInvokeArgs();
    }


    [OutputType]
    public sealed class GetVbInstanceApplicationsResult
    {
        /// <summary>
        /// The list of application_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVbInstanceApplicationsApplicationSummaryCollectionResult> ApplicationSummaryCollections;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? IdcsOpenId;
        public readonly string VbInstanceId;

        [OutputConstructor]
        private GetVbInstanceApplicationsResult(
            ImmutableArray<Outputs.GetVbInstanceApplicationsApplicationSummaryCollectionResult> applicationSummaryCollections,

            string id,

            string? idcsOpenId,

            string vbInstanceId)
        {
            ApplicationSummaryCollections = applicationSummaryCollections;
            Id = id;
            IdcsOpenId = idcsOpenId;
            VbInstanceId = vbInstanceId;
        }
    }
}