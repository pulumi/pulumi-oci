// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns
{
    public static class GetSteeringPolicyAttachment
    {
        /// <summary>
        /// This data source provides details about a specific Steering Policy Attachment resource in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets information about the specified steering policy attachment.
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
        ///     var testSteeringPolicyAttachment = Oci.Dns.GetSteeringPolicyAttachment.Invoke(new()
        ///     {
        ///         SteeringPolicyAttachmentId = testSteeringPolicyAttachmentOciDnsSteeringPolicyAttachment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSteeringPolicyAttachmentResult> InvokeAsync(GetSteeringPolicyAttachmentArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSteeringPolicyAttachmentResult>("oci:Dns/getSteeringPolicyAttachment:getSteeringPolicyAttachment", args ?? new GetSteeringPolicyAttachmentArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Steering Policy Attachment resource in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets information about the specified steering policy attachment.
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
        ///     var testSteeringPolicyAttachment = Oci.Dns.GetSteeringPolicyAttachment.Invoke(new()
        ///     {
        ///         SteeringPolicyAttachmentId = testSteeringPolicyAttachmentOciDnsSteeringPolicyAttachment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSteeringPolicyAttachmentResult> Invoke(GetSteeringPolicyAttachmentInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSteeringPolicyAttachmentResult>("oci:Dns/getSteeringPolicyAttachment:getSteeringPolicyAttachment", args ?? new GetSteeringPolicyAttachmentInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Steering Policy Attachment resource in Oracle Cloud Infrastructure DNS service.
        /// 
        /// Gets information about the specified steering policy attachment.
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
        ///     var testSteeringPolicyAttachment = Oci.Dns.GetSteeringPolicyAttachment.Invoke(new()
        ///     {
        ///         SteeringPolicyAttachmentId = testSteeringPolicyAttachmentOciDnsSteeringPolicyAttachment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSteeringPolicyAttachmentResult> Invoke(GetSteeringPolicyAttachmentInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSteeringPolicyAttachmentResult>("oci:Dns/getSteeringPolicyAttachment:getSteeringPolicyAttachment", args ?? new GetSteeringPolicyAttachmentInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSteeringPolicyAttachmentArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the target steering policy attachment.
        /// </summary>
        [Input("steeringPolicyAttachmentId", required: true)]
        public string SteeringPolicyAttachmentId { get; set; } = null!;

        public GetSteeringPolicyAttachmentArgs()
        {
        }
        public static new GetSteeringPolicyAttachmentArgs Empty => new GetSteeringPolicyAttachmentArgs();
    }

    public sealed class GetSteeringPolicyAttachmentInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the target steering policy attachment.
        /// </summary>
        [Input("steeringPolicyAttachmentId", required: true)]
        public Input<string> SteeringPolicyAttachmentId { get; set; } = null!;

        public GetSteeringPolicyAttachmentInvokeArgs()
        {
        }
        public static new GetSteeringPolicyAttachmentInvokeArgs Empty => new GetSteeringPolicyAttachmentInvokeArgs();
    }


    [OutputType]
    public sealed class GetSteeringPolicyAttachmentResult
    {
        /// <summary>
        /// The OCID of the compartment containing the steering policy attachment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly name for the steering policy attachment. Does not have to be unique and can be changed. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The attached domain within the attached zone.
        /// </summary>
        public readonly string DomainName;
        /// <summary>
        /// The OCID of the resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The record types covered by the attachment at the domain. The set of record types is determined by aggregating the record types from the answers defined in the steering policy.
        /// </summary>
        public readonly ImmutableArray<string> Rtypes;
        /// <summary>
        /// The canonical absolute URL of the resource.
        /// </summary>
        public readonly string Self;
        /// <summary>
        /// The current state of the resource.
        /// </summary>
        public readonly string State;
        public readonly string SteeringPolicyAttachmentId;
        /// <summary>
        /// The OCID of the attached steering policy.
        /// </summary>
        public readonly string SteeringPolicyId;
        /// <summary>
        /// The date and time the resource was created, expressed in RFC 3339 timestamp format.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The OCID of the attached zone.
        /// </summary>
        public readonly string ZoneId;

        [OutputConstructor]
        private GetSteeringPolicyAttachmentResult(
            string compartmentId,

            string displayName,

            string domainName,

            string id,

            ImmutableArray<string> rtypes,

            string self,

            string state,

            string steeringPolicyAttachmentId,

            string steeringPolicyId,

            string timeCreated,

            string zoneId)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            DomainName = domainName;
            Id = id;
            Rtypes = rtypes;
            Self = self;
            State = state;
            SteeringPolicyAttachmentId = steeringPolicyAttachmentId;
            SteeringPolicyId = steeringPolicyId;
            TimeCreated = timeCreated;
            ZoneId = zoneId;
        }
    }
}
