// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.RecoveryMod
{
    public static class GetProtectedDatabaseFetchConfiguration
    {
        /// <summary>
        /// This data source provides details about a specific Protected Database Fetch Configuration resource in Oracle Cloud Infrastructure Recovery service.
        /// 
        /// Downloads the network service configuration file 'tnsnames.ora' for a specified protected database. Applies to user-defined recovery systems only.
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
        ///     var testProtectedDatabaseFetchConfiguration = Oci.RecoveryMod.GetProtectedDatabaseFetchConfiguration.Invoke(new()
        ///     {
        ///         ProtectedDatabaseId = oci_recovery_protected_database.Test_protected_database.Id,
        ///         Base64EncodeContent = true,
        ///         ConfigurationType = @var.Protected_database_fetch_configuration_configuration_type,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetProtectedDatabaseFetchConfigurationResult> InvokeAsync(GetProtectedDatabaseFetchConfigurationArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetProtectedDatabaseFetchConfigurationResult>("oci:RecoveryMod/getProtectedDatabaseFetchConfiguration:getProtectedDatabaseFetchConfiguration", args ?? new GetProtectedDatabaseFetchConfigurationArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Protected Database Fetch Configuration resource in Oracle Cloud Infrastructure Recovery service.
        /// 
        /// Downloads the network service configuration file 'tnsnames.ora' for a specified protected database. Applies to user-defined recovery systems only.
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
        ///     var testProtectedDatabaseFetchConfiguration = Oci.RecoveryMod.GetProtectedDatabaseFetchConfiguration.Invoke(new()
        ///     {
        ///         ProtectedDatabaseId = oci_recovery_protected_database.Test_protected_database.Id,
        ///         Base64EncodeContent = true,
        ///         ConfigurationType = @var.Protected_database_fetch_configuration_configuration_type,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetProtectedDatabaseFetchConfigurationResult> Invoke(GetProtectedDatabaseFetchConfigurationInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetProtectedDatabaseFetchConfigurationResult>("oci:RecoveryMod/getProtectedDatabaseFetchConfiguration:getProtectedDatabaseFetchConfiguration", args ?? new GetProtectedDatabaseFetchConfigurationInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetProtectedDatabaseFetchConfigurationArgs : global::Pulumi.InvokeArgs
    {
        [Input("base64EncodeContent")]
        public bool? Base64EncodeContent { get; set; }

        /// <summary>
        /// Currently has four config options ALL, TNSNAMES, HOSTS and CABUNDLE. All will return a zipped folder containing the contents of both tnsnames and the certificateChainPem.
        /// </summary>
        [Input("configurationType")]
        public string? ConfigurationType { get; set; }

        /// <summary>
        /// The protected database OCID.
        /// </summary>
        [Input("protectedDatabaseId", required: true)]
        public string ProtectedDatabaseId { get; set; } = null!;

        public GetProtectedDatabaseFetchConfigurationArgs()
        {
        }
        public static new GetProtectedDatabaseFetchConfigurationArgs Empty => new GetProtectedDatabaseFetchConfigurationArgs();
    }

    public sealed class GetProtectedDatabaseFetchConfigurationInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("base64EncodeContent")]
        public Input<bool>? Base64EncodeContent { get; set; }

        /// <summary>
        /// Currently has four config options ALL, TNSNAMES, HOSTS and CABUNDLE. All will return a zipped folder containing the contents of both tnsnames and the certificateChainPem.
        /// </summary>
        [Input("configurationType")]
        public Input<string>? ConfigurationType { get; set; }

        /// <summary>
        /// The protected database OCID.
        /// </summary>
        [Input("protectedDatabaseId", required: true)]
        public Input<string> ProtectedDatabaseId { get; set; } = null!;

        public GetProtectedDatabaseFetchConfigurationInvokeArgs()
        {
        }
        public static new GetProtectedDatabaseFetchConfigurationInvokeArgs Empty => new GetProtectedDatabaseFetchConfigurationInvokeArgs();
    }


    [OutputType]
    public sealed class GetProtectedDatabaseFetchConfigurationResult
    {
        public readonly bool? Base64EncodeContent;
        public readonly string? ConfigurationType;
        /// <summary>
        /// content of the downloaded config file for recovery service. It is base64 encoded by default. To store the config in plaintext set `base_64_encode_content` to false.
        /// </summary>
        public readonly string Content;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string ProtectedDatabaseId;

        [OutputConstructor]
        private GetProtectedDatabaseFetchConfigurationResult(
            bool? base64EncodeContent,

            string? configurationType,

            string content,

            string id,

            string protectedDatabaseId)
        {
            Base64EncodeContent = base64EncodeContent;
            ConfigurationType = configurationType;
            Content = content;
            Id = id;
            ProtectedDatabaseId = protectedDatabaseId;
        }
    }
}