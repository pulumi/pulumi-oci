// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetFusionEnvironmentServiceAttachments
    {
        /// <summary>
        /// This data source provides the list of Fusion Environment Service Attachments in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Returns a list of service attachments.
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
        ///     var testFusionEnvironmentServiceAttachments = Oci.Functions.GetFusionEnvironmentServiceAttachments.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = oci_fusion_apps_fusion_environment.Test_fusion_environment.Id,
        ///         DisplayName = @var.Fusion_environment_service_attachment_display_name,
        ///         ServiceInstanceType = @var.Fusion_environment_service_attachment_service_instance_type,
        ///         State = @var.Fusion_environment_service_attachment_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetFusionEnvironmentServiceAttachmentsResult> InvokeAsync(GetFusionEnvironmentServiceAttachmentsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFusionEnvironmentServiceAttachmentsResult>("oci:Functions/getFusionEnvironmentServiceAttachments:getFusionEnvironmentServiceAttachments", args ?? new GetFusionEnvironmentServiceAttachmentsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Fusion Environment Service Attachments in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Returns a list of service attachments.
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
        ///     var testFusionEnvironmentServiceAttachments = Oci.Functions.GetFusionEnvironmentServiceAttachments.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = oci_fusion_apps_fusion_environment.Test_fusion_environment.Id,
        ///         DisplayName = @var.Fusion_environment_service_attachment_display_name,
        ///         ServiceInstanceType = @var.Fusion_environment_service_attachment_service_instance_type,
        ///         State = @var.Fusion_environment_service_attachment_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetFusionEnvironmentServiceAttachmentsResult> Invoke(GetFusionEnvironmentServiceAttachmentsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentServiceAttachmentsResult>("oci:Functions/getFusionEnvironmentServiceAttachments:getFusionEnvironmentServiceAttachments", args ?? new GetFusionEnvironmentServiceAttachmentsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFusionEnvironmentServiceAttachmentsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetFusionEnvironmentServiceAttachmentsFilterArgs>? _filters;
        public List<Inputs.GetFusionEnvironmentServiceAttachmentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetFusionEnvironmentServiceAttachmentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique FusionEnvironment identifier
        /// </summary>
        [Input("fusionEnvironmentId", required: true)]
        public string FusionEnvironmentId { get; set; } = null!;

        /// <summary>
        /// A filter that returns all resources that match the specified lifecycle state.
        /// </summary>
        [Input("serviceInstanceType")]
        public string? ServiceInstanceType { get; set; }

        /// <summary>
        /// A filter that returns all resources that match the specified lifecycle state.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetFusionEnvironmentServiceAttachmentsArgs()
        {
        }
        public static new GetFusionEnvironmentServiceAttachmentsArgs Empty => new GetFusionEnvironmentServiceAttachmentsArgs();
    }

    public sealed class GetFusionEnvironmentServiceAttachmentsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetFusionEnvironmentServiceAttachmentsFilterInputArgs>? _filters;
        public InputList<Inputs.GetFusionEnvironmentServiceAttachmentsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetFusionEnvironmentServiceAttachmentsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// unique FusionEnvironment identifier
        /// </summary>
        [Input("fusionEnvironmentId", required: true)]
        public Input<string> FusionEnvironmentId { get; set; } = null!;

        /// <summary>
        /// A filter that returns all resources that match the specified lifecycle state.
        /// </summary>
        [Input("serviceInstanceType")]
        public Input<string>? ServiceInstanceType { get; set; }

        /// <summary>
        /// A filter that returns all resources that match the specified lifecycle state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetFusionEnvironmentServiceAttachmentsInvokeArgs()
        {
        }
        public static new GetFusionEnvironmentServiceAttachmentsInvokeArgs Empty => new GetFusionEnvironmentServiceAttachmentsInvokeArgs();
    }


    [OutputType]
    public sealed class GetFusionEnvironmentServiceAttachmentsResult
    {
        /// <summary>
        /// Service Attachment Display name, can be renamed
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentServiceAttachmentsFilterResult> Filters;
        public readonly string FusionEnvironmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of service_attachment_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionResult> ServiceAttachmentCollections;
        /// <summary>
        /// Type of the serviceInstance.
        /// </summary>
        public readonly string? ServiceInstanceType;
        /// <summary>
        /// The current state of the ServiceInstance.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetFusionEnvironmentServiceAttachmentsResult(
            string? displayName,

            ImmutableArray<Outputs.GetFusionEnvironmentServiceAttachmentsFilterResult> filters,

            string fusionEnvironmentId,

            string id,

            ImmutableArray<Outputs.GetFusionEnvironmentServiceAttachmentsServiceAttachmentCollectionResult> serviceAttachmentCollections,

            string? serviceInstanceType,

            string? state)
        {
            DisplayName = displayName;
            Filters = filters;
            FusionEnvironmentId = fusionEnvironmentId;
            Id = id;
            ServiceAttachmentCollections = serviceAttachmentCollections;
            ServiceInstanceType = serviceInstanceType;
            State = state;
        }
    }
}