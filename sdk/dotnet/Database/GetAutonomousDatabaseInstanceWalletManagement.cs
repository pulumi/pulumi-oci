// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetAutonomousDatabaseInstanceWalletManagement
    {
        /// <summary>
        /// This data source provides details about a specific Autonomous Database Instance Wallet Management resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the wallet details for the specified Autonomous Database.
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
        ///     var testAutonomousDatabaseInstanceWalletManagement = Oci.Database.GetAutonomousDatabaseInstanceWalletManagement.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAutonomousDatabaseInstanceWalletManagementResult> InvokeAsync(GetAutonomousDatabaseInstanceWalletManagementArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAutonomousDatabaseInstanceWalletManagementResult>("oci:Database/getAutonomousDatabaseInstanceWalletManagement:getAutonomousDatabaseInstanceWalletManagement", args ?? new GetAutonomousDatabaseInstanceWalletManagementArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Autonomous Database Instance Wallet Management resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the wallet details for the specified Autonomous Database.
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
        ///     var testAutonomousDatabaseInstanceWalletManagement = Oci.Database.GetAutonomousDatabaseInstanceWalletManagement.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabaseInstanceWalletManagementResult> Invoke(GetAutonomousDatabaseInstanceWalletManagementInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseInstanceWalletManagementResult>("oci:Database/getAutonomousDatabaseInstanceWalletManagement:getAutonomousDatabaseInstanceWalletManagement", args ?? new GetAutonomousDatabaseInstanceWalletManagementInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Autonomous Database Instance Wallet Management resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the wallet details for the specified Autonomous Database.
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
        ///     var testAutonomousDatabaseInstanceWalletManagement = Oci.Database.GetAutonomousDatabaseInstanceWalletManagement.Invoke(new()
        ///     {
        ///         AutonomousDatabaseId = testAutonomousDatabase.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAutonomousDatabaseInstanceWalletManagementResult> Invoke(GetAutonomousDatabaseInstanceWalletManagementInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAutonomousDatabaseInstanceWalletManagementResult>("oci:Database/getAutonomousDatabaseInstanceWalletManagement:getAutonomousDatabaseInstanceWalletManagement", args ?? new GetAutonomousDatabaseInstanceWalletManagementInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAutonomousDatabaseInstanceWalletManagementArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public string AutonomousDatabaseId { get; set; } = null!;

        public GetAutonomousDatabaseInstanceWalletManagementArgs()
        {
        }
        public static new GetAutonomousDatabaseInstanceWalletManagementArgs Empty => new GetAutonomousDatabaseInstanceWalletManagementArgs();
    }

    public sealed class GetAutonomousDatabaseInstanceWalletManagementInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("autonomousDatabaseId", required: true)]
        public Input<string> AutonomousDatabaseId { get; set; } = null!;

        public GetAutonomousDatabaseInstanceWalletManagementInvokeArgs()
        {
        }
        public static new GetAutonomousDatabaseInstanceWalletManagementInvokeArgs Empty => new GetAutonomousDatabaseInstanceWalletManagementInvokeArgs();
    }


    [OutputType]
    public sealed class GetAutonomousDatabaseInstanceWalletManagementResult
    {
        /// <summary>
        /// The database [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string AutonomousDatabaseId;
        public readonly int GracePeriod;
        public readonly string Id;
        /// <summary>
        /// Indicates whether to rotate the wallet or not. If `false`, the wallet will not be rotated. The default is `false`.
        /// </summary>
        public readonly bool ShouldRotate;
        /// <summary>
        /// The current lifecycle state of the Autonomous Database wallet.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the wallet was last rotated.
        /// </summary>
        public readonly string TimeRotated;

        [OutputConstructor]
        private GetAutonomousDatabaseInstanceWalletManagementResult(
            string autonomousDatabaseId,

            int gracePeriod,

            string id,

            bool shouldRotate,

            string state,

            string timeRotated)
        {
            AutonomousDatabaseId = autonomousDatabaseId;
            GracePeriod = gracePeriod;
            Id = id;
            ShouldRotate = shouldRotate;
            State = state;
            TimeRotated = timeRotated;
        }
    }
}
