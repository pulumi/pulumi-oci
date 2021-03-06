// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    public static class GetInstanceCredentials
    {
        /// <summary>
        /// This data source provides details about a specific Instance Credential resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the generated credentials for the instance. Only works for instances that require a password to log in, such as Windows.
        /// For certain operating systems, users will be forced to change the initial credentials.
        /// 
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
        ///         var testInstanceCredential = Output.Create(Oci.Core.GetInstanceCredentials.InvokeAsync(new Oci.Core.GetInstanceCredentialsArgs
        ///         {
        ///             InstanceId = oci_core_instance.Test_instance.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetInstanceCredentialsResult> InvokeAsync(GetInstanceCredentialsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetInstanceCredentialsResult>("oci:Core/getInstanceCredentials:getInstanceCredentials", args ?? new GetInstanceCredentialsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Instance Credential resource in Oracle Cloud Infrastructure Core service.
        /// 
        /// Gets the generated credentials for the instance. Only works for instances that require a password to log in, such as Windows.
        /// For certain operating systems, users will be forced to change the initial credentials.
        /// 
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
        ///         var testInstanceCredential = Output.Create(Oci.Core.GetInstanceCredentials.InvokeAsync(new Oci.Core.GetInstanceCredentialsArgs
        ///         {
        ///             InstanceId = oci_core_instance.Test_instance.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetInstanceCredentialsResult> Invoke(GetInstanceCredentialsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetInstanceCredentialsResult>("oci:Core/getInstanceCredentials:getInstanceCredentials", args ?? new GetInstanceCredentialsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetInstanceCredentialsArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        [Input("instanceId", required: true)]
        public string InstanceId { get; set; } = null!;

        public GetInstanceCredentialsArgs()
        {
        }
    }

    public sealed class GetInstanceCredentialsInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
        /// </summary>
        [Input("instanceId", required: true)]
        public Input<string> InstanceId { get; set; } = null!;

        public GetInstanceCredentialsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetInstanceCredentialsResult
    {
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string InstanceId;
        /// <summary>
        /// The password for the username.
        /// </summary>
        public readonly string Password;
        /// <summary>
        /// The username.
        /// </summary>
        public readonly string Username;

        [OutputConstructor]
        private GetInstanceCredentialsResult(
            string id,

            string instanceId,

            string password,

            string username)
        {
            Id = id;
            InstanceId = instanceId;
            Password = password;
            Username = username;
        }
    }
}
