// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity
{
    public static class GetDomains
    {
        /// <summary>
        /// This data source provides the list of Domains in Oracle Cloud Infrastructure Identity service.
        /// 
        /// List all domains that are homed or have a replica region in current region.
        /// - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
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
        ///     var testDomains = Oci.Identity.GetDomains.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Domain_display_name,
        ///         HomeRegionUrl = @var.Domain_home_region_url,
        ///         IsHiddenOnLogin = @var.Domain_is_hidden_on_login,
        ///         LicenseType = @var.Domain_license_type,
        ///         Name = @var.Domain_name,
        ///         State = @var.Domain_state,
        ///         Type = @var.Domain_type,
        ///         Url = @var.Domain_url,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDomainsResult> InvokeAsync(GetDomainsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDomainsResult>("oci:Identity/getDomains:getDomains", args ?? new GetDomainsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Domains in Oracle Cloud Infrastructure Identity service.
        /// 
        /// List all domains that are homed or have a replica region in current region.
        /// - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
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
        ///     var testDomains = Oci.Identity.GetDomains.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Domain_display_name,
        ///         HomeRegionUrl = @var.Domain_home_region_url,
        ///         IsHiddenOnLogin = @var.Domain_is_hidden_on_login,
        ///         LicenseType = @var.Domain_license_type,
        ///         Name = @var.Domain_name,
        ///         State = @var.Domain_state,
        ///         Type = @var.Domain_type,
        ///         Url = @var.Domain_url,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDomainsResult> Invoke(GetDomainsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDomainsResult>("oci:Identity/getDomains:getDomains", args ?? new GetDomainsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDomainsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// The mutable display name of the domain
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetDomainsFilterArgs>? _filters;
        public List<Inputs.GetDomainsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetDomainsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The region specific domain URL
        /// </summary>
        [Input("homeRegionUrl")]
        public string? HomeRegionUrl { get; set; }

        /// <summary>
        /// Indicate if the domain is visible at login screen or not
        /// </summary>
        [Input("isHiddenOnLogin")]
        public bool? IsHiddenOnLogin { get; set; }

        /// <summary>
        /// The domain license type
        /// </summary>
        [Input("licenseType")]
        public string? LicenseType { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given name exactly.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        /// <summary>
        /// The domain type
        /// </summary>
        [Input("type")]
        public string? Type { get; set; }

        /// <summary>
        /// The region agnostic domain URL
        /// </summary>
        [Input("url")]
        public string? Url { get; set; }

        public GetDomainsArgs()
        {
        }
        public static new GetDomainsArgs Empty => new GetDomainsArgs();
    }

    public sealed class GetDomainsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the compartment (remember that the tenancy is simply the root compartment).
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// The mutable display name of the domain
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetDomainsFilterInputArgs>? _filters;
        public InputList<Inputs.GetDomainsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetDomainsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The region specific domain URL
        /// </summary>
        [Input("homeRegionUrl")]
        public Input<string>? HomeRegionUrl { get; set; }

        /// <summary>
        /// Indicate if the domain is visible at login screen or not
        /// </summary>
        [Input("isHiddenOnLogin")]
        public Input<bool>? IsHiddenOnLogin { get; set; }

        /// <summary>
        /// The domain license type
        /// </summary>
        [Input("licenseType")]
        public Input<string>? LicenseType { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given name exactly.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        /// <summary>
        /// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The domain type
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        /// <summary>
        /// The region agnostic domain URL
        /// </summary>
        [Input("url")]
        public Input<string>? Url { get; set; }

        public GetDomainsInvokeArgs()
        {
        }
        public static new GetDomainsInvokeArgs Empty => new GetDomainsInvokeArgs();
    }


    [OutputType]
    public sealed class GetDomainsResult
    {
        /// <summary>
        /// The OCID of the compartment containing the domain.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The mutable display name of the domain
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The list of domains.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDomainsDomainResult> Domains;
        public readonly ImmutableArray<Outputs.GetDomainsFilterResult> Filters;
        /// <summary>
        /// Region specific domain URL.
        /// </summary>
        public readonly string? HomeRegionUrl;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Indicates whether domain is hidden on login screen or not.
        /// </summary>
        public readonly bool? IsHiddenOnLogin;
        /// <summary>
        /// The License type of Domain
        /// </summary>
        public readonly string? LicenseType;
        public readonly string? Name;
        /// <summary>
        /// The current state.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The type of the domain.
        /// </summary>
        public readonly string? Type;
        /// <summary>
        /// Region agnostic domain URL.
        /// </summary>
        public readonly string? Url;

        [OutputConstructor]
        private GetDomainsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetDomainsDomainResult> domains,

            ImmutableArray<Outputs.GetDomainsFilterResult> filters,

            string? homeRegionUrl,

            string id,

            bool? isHiddenOnLogin,

            string? licenseType,

            string? name,

            string? state,

            string? type,

            string? url)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Domains = domains;
            Filters = filters;
            HomeRegionUrl = homeRegionUrl;
            Id = id;
            IsHiddenOnLogin = isHiddenOnLogin;
            LicenseType = licenseType;
            Name = name;
            State = state;
            Type = type;
            Url = url;
        }
    }
}