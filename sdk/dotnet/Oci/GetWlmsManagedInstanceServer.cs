// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci
{
    public static class GetWlmsManagedInstanceServer
    {
        /// <summary>
        /// This data source provides details about a specific Managed Instance Server resource in Oracle Cloud Infrastructure Wlms service.
        /// 
        /// Gets information about the specified server in a managed instance.
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
        ///     var testManagedInstanceServer = Oci.Oci.GetWlmsManagedInstanceServer.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ServerId = testServer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetWlmsManagedInstanceServerResult> InvokeAsync(GetWlmsManagedInstanceServerArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetWlmsManagedInstanceServerResult>("oci:oci/getWlmsManagedInstanceServer:getWlmsManagedInstanceServer", args ?? new GetWlmsManagedInstanceServerArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Instance Server resource in Oracle Cloud Infrastructure Wlms service.
        /// 
        /// Gets information about the specified server in a managed instance.
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
        ///     var testManagedInstanceServer = Oci.Oci.GetWlmsManagedInstanceServer.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ServerId = testServer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWlmsManagedInstanceServerResult> Invoke(GetWlmsManagedInstanceServerInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetWlmsManagedInstanceServerResult>("oci:oci/getWlmsManagedInstanceServer:getWlmsManagedInstanceServer", args ?? new GetWlmsManagedInstanceServerInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Managed Instance Server resource in Oracle Cloud Infrastructure Wlms service.
        /// 
        /// Gets information about the specified server in a managed instance.
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
        ///     var testManagedInstanceServer = Oci.Oci.GetWlmsManagedInstanceServer.Invoke(new()
        ///     {
        ///         ManagedInstanceId = testManagedInstance.Id,
        ///         ServerId = testServer.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWlmsManagedInstanceServerResult> Invoke(GetWlmsManagedInstanceServerInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetWlmsManagedInstanceServerResult>("oci:oci/getWlmsManagedInstanceServer:getWlmsManagedInstanceServer", args ?? new GetWlmsManagedInstanceServerInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWlmsManagedInstanceServerArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public string ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// The unique identifier of a server.
        /// 
        /// **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("serverId", required: true)]
        public string ServerId { get; set; } = null!;

        public GetWlmsManagedInstanceServerArgs()
        {
        }
        public static new GetWlmsManagedInstanceServerArgs Empty => new GetWlmsManagedInstanceServerArgs();
    }

    public sealed class GetWlmsManagedInstanceServerInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        [Input("managedInstanceId", required: true)]
        public Input<string> ManagedInstanceId { get; set; } = null!;

        /// <summary>
        /// The unique identifier of a server.
        /// 
        /// **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("serverId", required: true)]
        public Input<string> ServerId { get; set; } = null!;

        public GetWlmsManagedInstanceServerInvokeArgs()
        {
        }
        public static new GetWlmsManagedInstanceServerInvokeArgs Empty => new GetWlmsManagedInstanceServerInvokeArgs();
    }


    [OutputType]
    public sealed class GetWlmsManagedInstanceServerResult
    {
        /// <summary>
        /// The name of the server.
        /// </summary>
        public readonly string HostName;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether or not the server is an admin node.
        /// </summary>
        public readonly bool IsAdmin;
        /// <summary>
        /// The JDK path on the server.
        /// </summary>
        public readonly string JdkPath;
        /// <summary>
        /// The JDK version on the server.
        /// </summary>
        public readonly string JdkVersion;
        /// <summary>
        /// Whether or not the server has installed the latest patches.
        /// </summary>
        public readonly string LatestPatchesStatus;
        /// <summary>
        /// The managed instance ID of the server.
        /// </summary>
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The middleware path on the server.
        /// </summary>
        public readonly string MiddlewarePath;
        /// <summary>
        /// The middleware type on the server.
        /// </summary>
        public readonly string MiddlewareType;
        /// <summary>
        /// The name of the server.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// The patch readiness status of the server.
        /// </summary>
        public readonly string PatchReadinessStatus;
        /// <summary>
        /// The restart order assigned to the server.
        /// </summary>
        public readonly int RestartOrder;
        public readonly string ServerId;
        /// <summary>
        /// The status of the server.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The date and time the server was first reported (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the server was last reported (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// The version of the WebLogic domain of the server
        /// </summary>
        public readonly string WeblogicVersion;
        /// <summary>
        /// The ID of the WebLogic domain to which the server belongs.
        /// </summary>
        public readonly string WlsDomainId;
        /// <summary>
        /// The name of the WebLogic domain to which the server belongs.
        /// </summary>
        public readonly string WlsDomainName;
        /// <summary>
        /// The path of the WebLogic domain to which the server belongs.
        /// </summary>
        public readonly string WlsDomainPath;

        [OutputConstructor]
        private GetWlmsManagedInstanceServerResult(
            string hostName,

            string id,

            bool isAdmin,

            string jdkPath,

            string jdkVersion,

            string latestPatchesStatus,

            string managedInstanceId,

            string middlewarePath,

            string middlewareType,

            string name,

            string patchReadinessStatus,

            int restartOrder,

            string serverId,

            string status,

            string timeCreated,

            string timeUpdated,

            string weblogicVersion,

            string wlsDomainId,

            string wlsDomainName,

            string wlsDomainPath)
        {
            HostName = hostName;
            Id = id;
            IsAdmin = isAdmin;
            JdkPath = jdkPath;
            JdkVersion = jdkVersion;
            LatestPatchesStatus = latestPatchesStatus;
            ManagedInstanceId = managedInstanceId;
            MiddlewarePath = middlewarePath;
            MiddlewareType = middlewareType;
            Name = name;
            PatchReadinessStatus = patchReadinessStatus;
            RestartOrder = restartOrder;
            ServerId = serverId;
            Status = status;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            WeblogicVersion = weblogicVersion;
            WlsDomainId = wlsDomainId;
            WlsDomainName = wlsDomainName;
            WlsDomainPath = wlsDomainPath;
        }
    }
}
