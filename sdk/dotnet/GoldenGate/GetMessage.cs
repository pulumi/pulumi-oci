// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.GoldenGate
{
    public static class GetMessage
    {
        /// <summary>
        /// This data source provides details about a specific Message resource in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Lists the DeploymentMessages for a deployment. The sorting order is not important. By default first will be Upgrade message, next Exception message and then Storage Utilization message.
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
        ///     var testMessage = Oci.GoldenGate.GetMessage.Invoke(new()
        ///     {
        ///         DeploymentId = oci_golden_gate_deployment.Test_deployment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetMessageResult> InvokeAsync(GetMessageArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMessageResult>("oci:GoldenGate/getMessage:getMessage", args ?? new GetMessageArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Message resource in Oracle Cloud Infrastructure Golden Gate service.
        /// 
        /// Lists the DeploymentMessages for a deployment. The sorting order is not important. By default first will be Upgrade message, next Exception message and then Storage Utilization message.
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
        ///     var testMessage = Oci.GoldenGate.GetMessage.Invoke(new()
        ///     {
        ///         DeploymentId = oci_golden_gate_deployment.Test_deployment.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetMessageResult> Invoke(GetMessageInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMessageResult>("oci:GoldenGate/getMessage:getMessage", args ?? new GetMessageInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMessageArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique Deployment identifier.
        /// </summary>
        [Input("deploymentId", required: true)]
        public string DeploymentId { get; set; } = null!;

        public GetMessageArgs()
        {
        }
        public static new GetMessageArgs Empty => new GetMessageArgs();
    }

    public sealed class GetMessageInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A unique Deployment identifier.
        /// </summary>
        [Input("deploymentId", required: true)]
        public Input<string> DeploymentId { get; set; } = null!;

        public GetMessageInvokeArgs()
        {
        }
        public static new GetMessageInvokeArgs Empty => new GetMessageInvokeArgs();
    }


    [OutputType]
    public sealed class GetMessageResult
    {
        public readonly string DeploymentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// An array of DeploymentMessages.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMessageItemResult> Items;

        [OutputConstructor]
        private GetMessageResult(
            string deploymentId,

            string id,

            ImmutableArray<Outputs.GetMessageItemResult> items)
        {
            DeploymentId = deploymentId;
            Id = id;
            Items = items;
        }
    }
}