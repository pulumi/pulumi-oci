// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms
{
    public static class GetJavaReleases
    {
        /// <summary>
        /// This data source provides the list of Java Releases in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of Java releases.
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
        ///     var testJavaReleases = Oci.Jms.GetJavaReleases.Invoke(new()
        ///     {
        ///         FamilyVersion = javaReleaseFamilyVersion,
        ///         JreSecurityStatus = javaReleaseJreSecurityStatus,
        ///         LicenseType = javaReleaseLicenseType,
        ///         ReleaseType = javaReleaseReleaseType,
        ///         ReleaseVersion = javaReleaseReleaseVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetJavaReleasesResult> InvokeAsync(GetJavaReleasesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetJavaReleasesResult>("oci:Jms/getJavaReleases:getJavaReleases", args ?? new GetJavaReleasesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Java Releases in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of Java releases.
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
        ///     var testJavaReleases = Oci.Jms.GetJavaReleases.Invoke(new()
        ///     {
        ///         FamilyVersion = javaReleaseFamilyVersion,
        ///         JreSecurityStatus = javaReleaseJreSecurityStatus,
        ///         LicenseType = javaReleaseLicenseType,
        ///         ReleaseType = javaReleaseReleaseType,
        ///         ReleaseVersion = javaReleaseReleaseVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetJavaReleasesResult> Invoke(GetJavaReleasesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetJavaReleasesResult>("oci:Jms/getJavaReleases:getJavaReleases", args ?? new GetJavaReleasesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Java Releases in Oracle Cloud Infrastructure Jms service.
        /// 
        /// Returns a list of Java releases.
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
        ///     var testJavaReleases = Oci.Jms.GetJavaReleases.Invoke(new()
        ///     {
        ///         FamilyVersion = javaReleaseFamilyVersion,
        ///         JreSecurityStatus = javaReleaseJreSecurityStatus,
        ///         LicenseType = javaReleaseLicenseType,
        ///         ReleaseType = javaReleaseReleaseType,
        ///         ReleaseVersion = javaReleaseReleaseVersion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetJavaReleasesResult> Invoke(GetJavaReleasesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetJavaReleasesResult>("oci:Jms/getJavaReleases:getJavaReleases", args ?? new GetJavaReleasesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetJavaReleasesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The version identifier for the Java family.
        /// </summary>
        [Input("familyVersion")]
        public string? FamilyVersion { get; set; }

        [Input("filters")]
        private List<Inputs.GetJavaReleasesFilterArgs>? _filters;
        public List<Inputs.GetJavaReleasesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetJavaReleasesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The security status of the Java Runtime.
        /// </summary>
        [Input("jreSecurityStatus")]
        public string? JreSecurityStatus { get; set; }

        /// <summary>
        /// Java license type.
        /// </summary>
        [Input("licenseType")]
        public string? LicenseType { get; set; }

        /// <summary>
        /// Java release type.
        /// </summary>
        [Input("releaseType")]
        public string? ReleaseType { get; set; }

        /// <summary>
        /// Unique Java release version identifier
        /// </summary>
        [Input("releaseVersion")]
        public string? ReleaseVersion { get; set; }

        public GetJavaReleasesArgs()
        {
        }
        public static new GetJavaReleasesArgs Empty => new GetJavaReleasesArgs();
    }

    public sealed class GetJavaReleasesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The version identifier for the Java family.
        /// </summary>
        [Input("familyVersion")]
        public Input<string>? FamilyVersion { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetJavaReleasesFilterInputArgs>? _filters;
        public InputList<Inputs.GetJavaReleasesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetJavaReleasesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The security status of the Java Runtime.
        /// </summary>
        [Input("jreSecurityStatus")]
        public Input<string>? JreSecurityStatus { get; set; }

        /// <summary>
        /// Java license type.
        /// </summary>
        [Input("licenseType")]
        public Input<string>? LicenseType { get; set; }

        /// <summary>
        /// Java release type.
        /// </summary>
        [Input("releaseType")]
        public Input<string>? ReleaseType { get; set; }

        /// <summary>
        /// Unique Java release version identifier
        /// </summary>
        [Input("releaseVersion")]
        public Input<string>? ReleaseVersion { get; set; }

        public GetJavaReleasesInvokeArgs()
        {
        }
        public static new GetJavaReleasesInvokeArgs Empty => new GetJavaReleasesInvokeArgs();
    }


    [OutputType]
    public sealed class GetJavaReleasesResult
    {
        /// <summary>
        /// Java release family identifier.
        /// </summary>
        public readonly string? FamilyVersion;
        public readonly ImmutableArray<Outputs.GetJavaReleasesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of java_release_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetJavaReleasesJavaReleaseCollectionResult> JavaReleaseCollections;
        public readonly string? JreSecurityStatus;
        /// <summary>
        /// License type for the Java version.
        /// </summary>
        public readonly string? LicenseType;
        /// <summary>
        /// Release category of the Java version.
        /// </summary>
        public readonly string? ReleaseType;
        /// <summary>
        /// Java release version identifier.
        /// </summary>
        public readonly string? ReleaseVersion;

        [OutputConstructor]
        private GetJavaReleasesResult(
            string? familyVersion,

            ImmutableArray<Outputs.GetJavaReleasesFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetJavaReleasesJavaReleaseCollectionResult> javaReleaseCollections,

            string? jreSecurityStatus,

            string? licenseType,

            string? releaseType,

            string? releaseVersion)
        {
            FamilyVersion = familyVersion;
            Filters = filters;
            Id = id;
            JavaReleaseCollections = javaReleaseCollections;
            JreSecurityStatus = jreSecurityStatus;
            LicenseType = licenseType;
            ReleaseType = releaseType;
            ReleaseVersion = releaseVersion;
        }
    }
}
