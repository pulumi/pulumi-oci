// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudGuard
{
    public static class GetWlpAgent
    {
        /// <summary>
        /// This data source provides details about a specific Wlp Agent resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a WlpAgent resource for an on-premise resource identified by wlpAgentId.
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
        ///     var testWlpAgent = Oci.CloudGuard.GetWlpAgent.Invoke(new()
        ///     {
        ///         WlpAgentId = testWlpAgentOciCloudGuardWlpAgent.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetWlpAgentResult> InvokeAsync(GetWlpAgentArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetWlpAgentResult>("oci:CloudGuard/getWlpAgent:getWlpAgent", args ?? new GetWlpAgentArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Wlp Agent resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a WlpAgent resource for an on-premise resource identified by wlpAgentId.
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
        ///     var testWlpAgent = Oci.CloudGuard.GetWlpAgent.Invoke(new()
        ///     {
        ///         WlpAgentId = testWlpAgentOciCloudGuardWlpAgent.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWlpAgentResult> Invoke(GetWlpAgentInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetWlpAgentResult>("oci:CloudGuard/getWlpAgent:getWlpAgent", args ?? new GetWlpAgentInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Wlp Agent resource in Oracle Cloud Infrastructure Cloud Guard service.
        /// 
        /// Returns a WlpAgent resource for an on-premise resource identified by wlpAgentId.
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
        ///     var testWlpAgent = Oci.CloudGuard.GetWlpAgent.Invoke(new()
        ///     {
        ///         WlpAgentId = testWlpAgentOciCloudGuardWlpAgent.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWlpAgentResult> Invoke(GetWlpAgentInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetWlpAgentResult>("oci:CloudGuard/getWlpAgent:getWlpAgent", args ?? new GetWlpAgentInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWlpAgentArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// WLP agent OCID.
        /// </summary>
        [Input("wlpAgentId", required: true)]
        public string WlpAgentId { get; set; } = null!;

        public GetWlpAgentArgs()
        {
        }
        public static new GetWlpAgentArgs Empty => new GetWlpAgentArgs();
    }

    public sealed class GetWlpAgentInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// WLP agent OCID.
        /// </summary>
        [Input("wlpAgentId", required: true)]
        public Input<string> WlpAgentId { get; set; } = null!;

        public GetWlpAgentInvokeArgs()
        {
        }
        public static new GetWlpAgentInvokeArgs Empty => new GetWlpAgentInvokeArgs();
    }


    [OutputType]
    public sealed class GetWlpAgentResult
    {
        /// <summary>
        /// The version of the agent
        /// </summary>
        public readonly string AgentVersion;
        /// <summary>
        /// The certificate ID returned by Oracle Cloud Infrastructure certificates service
        /// </summary>
        public readonly string CertificateId;
        /// <summary>
        /// The updated certificate signing request
        /// </summary>
        public readonly string CertificateSignedRequest;
        /// <summary>
        /// Compartment OCID of WlpAgent.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// OCID for instance in which WlpAgent is installed
        /// </summary>
        public readonly string HostId;
        /// <summary>
        /// OCID for WlpAgent
        /// </summary>
        public readonly string Id;
        public readonly string OsInfo;
        /// <summary>
        /// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// TenantId of the host
        /// </summary>
        public readonly string TenantId;
        /// <summary>
        /// The date and time the WlpAgent was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the WlpAgent was updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;
        public readonly string WlpAgentId;

        [OutputConstructor]
        private GetWlpAgentResult(
            string agentVersion,

            string certificateId,

            string certificateSignedRequest,

            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string hostId,

            string id,

            string osInfo,

            ImmutableDictionary<string, string> systemTags,

            string tenantId,

            string timeCreated,

            string timeUpdated,

            string wlpAgentId)
        {
            AgentVersion = agentVersion;
            CertificateId = certificateId;
            CertificateSignedRequest = certificateSignedRequest;
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            HostId = hostId;
            Id = id;
            OsInfo = osInfo;
            SystemTags = systemTags;
            TenantId = tenantId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            WlpAgentId = wlpAgentId;
        }
    }
}
