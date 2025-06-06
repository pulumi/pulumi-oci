// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetVnicAttachments
    {
        /// <summary>
        /// This data source provides the list of Vnic Attachments in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the VNIC attachments in the specified compartment. A VNIC attachment
        /// resides in the same compartment as the attached instance. The list can be
        /// filtered by instance, VNIC, or availability domain.
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
        ///     var testVnicAttachments = Oci.Core.GetVnicAttachments.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = vnicAttachmentAvailabilityDomain,
        ///         InstanceId = testInstance.Id,
        ///         VnicId = testVnic.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetVnicAttachmentsResult> InvokeAsync(GetVnicAttachmentsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetVnicAttachmentsResult>("oci:Core/getVnicAttachments:getVnicAttachments", args ?? new GetVnicAttachmentsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Vnic Attachments in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the VNIC attachments in the specified compartment. A VNIC attachment
        /// resides in the same compartment as the attached instance. The list can be
        /// filtered by instance, VNIC, or availability domain.
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
        ///     var testVnicAttachments = Oci.Core.GetVnicAttachments.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = vnicAttachmentAvailabilityDomain,
        ///         InstanceId = testInstance.Id,
        ///         VnicId = testVnic.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetVnicAttachmentsResult> Invoke(GetVnicAttachmentsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetVnicAttachmentsResult>("oci:Core/getVnicAttachments:getVnicAttachments", args ?? new GetVnicAttachmentsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Vnic Attachments in Oracle Cloud Infrastructure Core service.
        /// 
        /// Lists the VNIC attachments in the specified compartment. A VNIC attachment
        /// resides in the same compartment as the attached instance. The list can be
        /// filtered by instance, VNIC, or availability domain.
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
        ///     var testVnicAttachments = Oci.Core.GetVnicAttachments.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         AvailabilityDomain = vnicAttachmentAvailabilityDomain,
        ///         InstanceId = testInstance.Id,
        ///         VnicId = testVnic.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetVnicAttachmentsResult> Invoke(GetVnicAttachmentsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetVnicAttachmentsResult>("oci:Core/getVnicAttachments:getVnicAttachments", args ?? new GetVnicAttachmentsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetVnicAttachmentsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetVnicAttachmentsFilterArgs>? _filters;
        public List<Inputs.GetVnicAttachmentsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetVnicAttachmentsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceId")]
        public string? InstanceId { get; set; }

        /// <summary>
        /// The OCID of the VNIC.
        /// </summary>
        [Input("vnicId")]
        public string? VnicId { get; set; }

        public GetVnicAttachmentsArgs()
        {
        }
        public static new GetVnicAttachmentsArgs Empty => new GetVnicAttachmentsArgs();
    }

    public sealed class GetVnicAttachmentsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetVnicAttachmentsFilterInputArgs>? _filters;
        public InputList<Inputs.GetVnicAttachmentsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetVnicAttachmentsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        [Input("instanceId")]
        public Input<string>? InstanceId { get; set; }

        /// <summary>
        /// The OCID of the VNIC.
        /// </summary>
        [Input("vnicId")]
        public Input<string>? VnicId { get; set; }

        public GetVnicAttachmentsInvokeArgs()
        {
        }
        public static new GetVnicAttachmentsInvokeArgs Empty => new GetVnicAttachmentsInvokeArgs();
    }


    [OutputType]
    public sealed class GetVnicAttachmentsResult
    {
        /// <summary>
        /// The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The OCID of the compartment the VNIC attachment is in, which is the same compartment the instance is in.
        /// </summary>
        public readonly string CompartmentId;
        public readonly ImmutableArray<Outputs.GetVnicAttachmentsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The OCID of the instance.
        /// </summary>
        public readonly string? InstanceId;
        /// <summary>
        /// The list of vnic_attachments.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetVnicAttachmentsVnicAttachmentResult> VnicAttachments;
        /// <summary>
        /// The OCID of the VNIC. Available after the attachment process is complete.
        /// </summary>
        public readonly string? VnicId;

        [OutputConstructor]
        private GetVnicAttachmentsResult(
            string? availabilityDomain,

            string compartmentId,

            ImmutableArray<Outputs.GetVnicAttachmentsFilterResult> filters,

            string id,

            string? instanceId,

            ImmutableArray<Outputs.GetVnicAttachmentsVnicAttachmentResult> vnicAttachments,

            string? vnicId)
        {
            AvailabilityDomain = availabilityDomain;
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            InstanceId = instanceId;
            VnicAttachments = vnicAttachments;
            VnicId = vnicId;
        }
    }
}
