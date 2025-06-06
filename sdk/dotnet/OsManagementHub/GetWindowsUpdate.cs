// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub
{
    public static class GetWindowsUpdate
    {
        /// <summary>
        /// This data source provides details about a specific Windows Update resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns a Windows Update object.
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
        ///     var testWindowsUpdate = Oci.OsManagementHub.GetWindowsUpdate.Invoke(new()
        ///     {
        ///         WindowsUpdateId = testWindowsUpdateOciOsManagementHubWindowsUpdate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetWindowsUpdateResult> InvokeAsync(GetWindowsUpdateArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetWindowsUpdateResult>("oci:OsManagementHub/getWindowsUpdate:getWindowsUpdate", args ?? new GetWindowsUpdateArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Windows Update resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns a Windows Update object.
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
        ///     var testWindowsUpdate = Oci.OsManagementHub.GetWindowsUpdate.Invoke(new()
        ///     {
        ///         WindowsUpdateId = testWindowsUpdateOciOsManagementHubWindowsUpdate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWindowsUpdateResult> Invoke(GetWindowsUpdateInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetWindowsUpdateResult>("oci:OsManagementHub/getWindowsUpdate:getWindowsUpdate", args ?? new GetWindowsUpdateInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Windows Update resource in Oracle Cloud Infrastructure Os Management Hub service.
        /// 
        /// Returns a Windows Update object.
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
        ///     var testWindowsUpdate = Oci.OsManagementHub.GetWindowsUpdate.Invoke(new()
        ///     {
        ///         WindowsUpdateId = testWindowsUpdateOciOsManagementHubWindowsUpdate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetWindowsUpdateResult> Invoke(GetWindowsUpdateInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetWindowsUpdateResult>("oci:OsManagementHub/getWindowsUpdate:getWindowsUpdate", args ?? new GetWindowsUpdateInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetWindowsUpdateArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        [Input("windowsUpdateId", required: true)]
        public string WindowsUpdateId { get; set; } = null!;

        public GetWindowsUpdateArgs()
        {
        }
        public static new GetWindowsUpdateArgs Empty => new GetWindowsUpdateArgs();
    }

    public sealed class GetWindowsUpdateInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        [Input("windowsUpdateId", required: true)]
        public Input<string> WindowsUpdateId { get; set; } = null!;

        public GetWindowsUpdateInvokeArgs()
        {
        }
        public static new GetWindowsUpdateInvokeArgs Empty => new GetWindowsUpdateInvokeArgs();
    }


    [OutputType]
    public sealed class GetWindowsUpdateResult
    {
        /// <summary>
        /// Description of the update.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether the update can be installed using the service.
        /// </summary>
        public readonly string Installable;
        /// <summary>
        /// List of requirements for installing the update on the managed instance.
        /// </summary>
        public readonly ImmutableArray<string> InstallationRequirements;
        /// <summary>
        /// Indicates whether a reboot is required to complete the installation of this update.
        /// </summary>
        public readonly bool IsRebootRequiredForInstallation;
        /// <summary>
        /// List of the Microsoft Knowledge Base Article Ids related to this Windows Update.
        /// </summary>
        public readonly ImmutableArray<string> KbArticleIds;
        /// <summary>
        /// Name of the Windows update.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// size of the package in bytes
        /// </summary>
        public readonly string SizeInBytes;
        /// <summary>
        /// Unique identifier for the Windows update. Note that this is not an OCID, but is a unique identifier assigned by Microsoft.  Example: '6981d463-cd91-4a26-b7c4-ea4ded9183ed'
        /// </summary>
        public readonly string UpdateId;
        /// <summary>
        /// The type of Windows update.
        /// </summary>
        public readonly string UpdateType;
        public readonly string WindowsUpdateId;

        [OutputConstructor]
        private GetWindowsUpdateResult(
            string description,

            string id,

            string installable,

            ImmutableArray<string> installationRequirements,

            bool isRebootRequiredForInstallation,

            ImmutableArray<string> kbArticleIds,

            string name,

            string sizeInBytes,

            string updateId,

            string updateType,

            string windowsUpdateId)
        {
            Description = description;
            Id = id;
            Installable = installable;
            InstallationRequirements = installationRequirements;
            IsRebootRequiredForInstallation = isRebootRequiredForInstallation;
            KbArticleIds = kbArticleIds;
            Name = name;
            SizeInBytes = sizeInBytes;
            UpdateId = updateId;
            UpdateType = updateType;
            WindowsUpdateId = windowsUpdateId;
        }
    }
}
