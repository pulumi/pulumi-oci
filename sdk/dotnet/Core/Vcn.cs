// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core
{
    /// <summary>
    /// This resource provides the Vcn resource in Oracle Cloud Infrastructure Core service.
    /// 
    /// The VCN automatically comes with a default route table, default security list, and default set of DHCP options.
    /// For managing these resources, see [Managing Default VCN Resources](https://www.terraform.io/docs/providers/oci/guides/managing_default_resources.html)
    /// 
    /// Creates a new Virtual Cloud Network (VCN). For more information, see
    /// [VCNs and Subnets](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVCNs.htm).
    /// 
    /// For the VCN, you specify a list of one or more IPv4 CIDR blocks that meet the following criteria:
    /// 
    /// - The CIDR blocks must be valid.
    /// - They must not overlap with each other or with the on-premises network CIDR block.
    /// - The number of CIDR blocks does not exceed the limit of CIDR blocks allowed per VCN.
    /// 
    /// For a CIDR block, Oracle recommends that you use one of the private IP address ranges specified in [RFC 1918](https://tools.ietf.org/html/rfc1918) (10.0.0.0/8, 172.16/12, and 192.168/16). Example:
    /// 172.16.0.0/16. The CIDR blocks can range from /16 to /30.
    /// 
    /// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the VCN to
    /// reside. Consult an Oracle Cloud Infrastructure administrator in your organization if you're not sure which
    /// compartment to use. Notice that the VCN doesn't have to be in the same compartment as the subnets or other
    /// Networking Service components. For more information about compartments and access control, see
    /// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm). For information about OCIDs, see
    /// [Resource Identifiers](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    /// 
    /// You may optionally specify a *display name* for the VCN, otherwise a default is provided. It does not have to
    /// be unique, and you can change it. Avoid entering confidential information.
    /// 
    /// You can also add a DNS label for the VCN, which is required if you want the instances to use the
    /// Interent and VCN Resolver option for DNS in the VCN. For more information, see
    /// [DNS in Your Virtual Cloud Network](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/dns.htm).
    /// 
    /// The VCN automatically comes with a default route table, default security list, and default set of DHCP options.
    /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for each is returned in the response. You can't delete these default objects, but you can change their
    /// contents (that is, change the route rules, security list rules, and so on).
    /// 
    /// The VCN and subnets you create are not accessible until you attach an internet gateway or set up a Site-to-Site VPN
    /// or FastConnect. For more information, see
    /// [Overview of the Networking Service](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/overview.htm).
    /// 
    /// ## Supported Aliases
    /// 
    /// * `oci.Core.VirtualNetwork`
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testVcn = new Oci.Core.Vcn("testVcn", new()
    ///     {
    ///         CompartmentId = @var.Compartment_id,
    ///         Byoipv6cidrDetails = new[]
    ///         {
    ///             new Oci.Core.Inputs.VcnByoipv6cidrDetailArgs
    ///             {
    ///                 Byoipv6rangeId = oci_core_byoipv6range.Test_byoipv6range.Id,
    ///                 Ipv6cidrBlock = @var.Vcn_byoipv6cidr_details_ipv6cidr_block,
    ///             },
    ///         },
    ///         CidrBlock = @var.Vcn_cidr_block,
    ///         CidrBlocks = @var.Vcn_cidr_blocks,
    ///         DefinedTags = 
    ///         {
    ///             { "Operations.CostCenter", "42" },
    ///         },
    ///         DisplayName = @var.Vcn_display_name,
    ///         DnsLabel = @var.Vcn_dns_label,
    ///         FreeformTags = 
    ///         {
    ///             { "Department", "Finance" },
    ///         },
    ///         Ipv6privateCidrBlocks = @var.Vcn_ipv6private_cidr_blocks,
    ///         IsIpv6enabled = @var.Vcn_is_ipv6enabled,
    ///         IsOracleGuaAllocationEnabled = @var.Vcn_is_oracle_gua_allocation_enabled,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// Vcns can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Core/vcn:Vcn test_vcn "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Core/vcn:Vcn")]
    public partial class Vcn : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The list of BYOIPv6 CIDR blocks required to create a VCN that uses BYOIPv6 ranges.
        /// </summary>
        [Output("byoipv6cidrBlocks")]
        public Output<ImmutableArray<string>> Byoipv6cidrBlocks { get; private set; } = null!;

        /// <summary>
        /// The list of BYOIPv6 OCIDs and BYOIPv6 CIDR blocks required to create a VCN that uses BYOIPv6 ranges.
        /// </summary>
        [Output("byoipv6cidrDetails")]
        public Output<ImmutableArray<Outputs.VcnByoipv6cidrDetail>> Byoipv6cidrDetails { get; private set; } = null!;

        /// <summary>
        /// **Deprecated.** Do *not* set this value. Use `cidrBlocks` instead. Example: `10.0.0.0/16`
        /// </summary>
        [Output("cidrBlock")]
        public Output<string> CidrBlock { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The list of one or more IPv4 CIDR blocks for the VCN that meet the following criteria:
        /// * The CIDR blocks must be valid.
        /// * They must not overlap with each other or with the on-premises network CIDR block.
        /// * The number of CIDR blocks must not exceed the limit of CIDR blocks allowed per VCN. It is an error to set both cidrBlock and cidrBlocks. Note: cidr_blocks update must be restricted to one operation at a time (either add/remove or modify one single cidr_block) or the operation will be declined. new cidr_block to be added must be placed at the end of the list. Once you migrate to using `cidr_blocks` from `cidr_block`, you will not be able to switch back.
        /// **Important:** Do *not* specify a value for `cidrBlock`. Use this parameter instead.
        /// </summary>
        [Output("cidrBlocks")]
        public Output<ImmutableArray<string>> CidrBlocks { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the VCN.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the VCN's default set of DHCP options.
        /// </summary>
        [Output("defaultDhcpOptionsId")]
        public Output<string> DefaultDhcpOptionsId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the VCN's default route table.
        /// </summary>
        [Output("defaultRouteTableId")]
        public Output<string> DefaultRouteTableId { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the VCN's default security list.
        /// </summary>
        [Output("defaultSecurityListId")]
        public Output<string> DefaultSecurityListId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, object>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Not required to be unique, but it's a best practice to set unique DNS labels for VCNs in your tenancy. Must be an alphanumeric string that begins with a letter. The value cannot be changed.
        /// </summary>
        [Output("dnsLabel")]
        public Output<string> DnsLabel { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, object>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// For an IPv6-enabled VCN, this is the list of IPv6 CIDR blocks for the VCN's IP address space. The CIDRs are provided by Oracle and the sizes are always /56.
        /// </summary>
        [Output("ipv6cidrBlocks")]
        public Output<ImmutableArray<string>> Ipv6cidrBlocks { get; private set; } = null!;

        /// <summary>
        /// The list of one or more ULA or Private IPv6 CIDR blocks for the vcn that meets the following criteria:
        /// * The CIDR blocks must be valid.
        /// * Multiple CIDR blocks must not overlap each other or the on-premises network CIDR block.
        /// * The number of CIDR blocks must not exceed the limit of IPv6 CIDR blocks allowed to a vcn.
        /// </summary>
        [Output("ipv6privateCidrBlocks")]
        public Output<ImmutableArray<string>> Ipv6privateCidrBlocks { get; private set; } = null!;

        /// <summary>
        /// Whether IPv6 is enabled for the VCN. Default is `false`. If enabled, Oracle will assign the VCN a IPv6 /56 CIDR block. You may skip having Oracle allocate the VCN a IPv6 /56 CIDR block by setting isOracleGuaAllocationEnabled to `false`. For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).  Example: `true`
        /// </summary>
        [Output("isIpv6enabled")]
        public Output<bool> IsIpv6enabled { get; private set; } = null!;

        /// <summary>
        /// Specifies whether to skip Oracle allocated IPv6 GUA. By default, Oracle will allocate one GUA of /56 size for an IPv6 enabled VCN.
        /// </summary>
        [Output("isOracleGuaAllocationEnabled")]
        public Output<bool> IsOracleGuaAllocationEnabled { get; private set; } = null!;

        /// <summary>
        /// The VCN's current state.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The date and time the VCN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The VCN's domain name, which consists of the VCN's DNS label, and the `oraclevcn.com` domain.
        /// </summary>
        [Output("vcnDomainName")]
        public Output<string> VcnDomainName { get; private set; } = null!;


        /// <summary>
        /// Create a Vcn resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Vcn(string name, VcnArgs args, CustomResourceOptions? options = null)
            : base("oci:Core/vcn:Vcn", name, args ?? new VcnArgs(), MakeResourceOptions(options, ""))
        {
        }

        private Vcn(string name, Input<string> id, VcnState? state = null, CustomResourceOptions? options = null)
            : base("oci:Core/vcn:Vcn", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing Vcn resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static Vcn Get(string name, Input<string> id, VcnState? state = null, CustomResourceOptions? options = null)
        {
            return new Vcn(name, id, state, options);
        }
    }

    public sealed class VcnArgs : global::Pulumi.ResourceArgs
    {
        [Input("byoipv6cidrDetails")]
        private InputList<Inputs.VcnByoipv6cidrDetailArgs>? _byoipv6cidrDetails;

        /// <summary>
        /// The list of BYOIPv6 OCIDs and BYOIPv6 CIDR blocks required to create a VCN that uses BYOIPv6 ranges.
        /// </summary>
        public InputList<Inputs.VcnByoipv6cidrDetailArgs> Byoipv6cidrDetails
        {
            get => _byoipv6cidrDetails ?? (_byoipv6cidrDetails = new InputList<Inputs.VcnByoipv6cidrDetailArgs>());
            set => _byoipv6cidrDetails = value;
        }

        /// <summary>
        /// **Deprecated.** Do *not* set this value. Use `cidrBlocks` instead. Example: `10.0.0.0/16`
        /// </summary>
        [Input("cidrBlock")]
        public Input<string>? CidrBlock { get; set; }

        [Input("cidrBlocks")]
        private InputList<string>? _cidrBlocks;

        /// <summary>
        /// (Updatable) The list of one or more IPv4 CIDR blocks for the VCN that meet the following criteria:
        /// * The CIDR blocks must be valid.
        /// * They must not overlap with each other or with the on-premises network CIDR block.
        /// * The number of CIDR blocks must not exceed the limit of CIDR blocks allowed per VCN. It is an error to set both cidrBlock and cidrBlocks. Note: cidr_blocks update must be restricted to one operation at a time (either add/remove or modify one single cidr_block) or the operation will be declined. new cidr_block to be added must be placed at the end of the list. Once you migrate to using `cidr_blocks` from `cidr_block`, you will not be able to switch back.
        /// **Important:** Do *not* specify a value for `cidrBlock`. Use this parameter instead.
        /// </summary>
        public InputList<string> CidrBlocks
        {
            get => _cidrBlocks ?? (_cidrBlocks = new InputList<string>());
            set => _cidrBlocks = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the VCN.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Not required to be unique, but it's a best practice to set unique DNS labels for VCNs in your tenancy. Must be an alphanumeric string that begins with a letter. The value cannot be changed.
        /// </summary>
        [Input("dnsLabel")]
        public Input<string>? DnsLabel { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("ipv6privateCidrBlocks")]
        private InputList<string>? _ipv6privateCidrBlocks;

        /// <summary>
        /// The list of one or more ULA or Private IPv6 CIDR blocks for the vcn that meets the following criteria:
        /// * The CIDR blocks must be valid.
        /// * Multiple CIDR blocks must not overlap each other or the on-premises network CIDR block.
        /// * The number of CIDR blocks must not exceed the limit of IPv6 CIDR blocks allowed to a vcn.
        /// </summary>
        public InputList<string> Ipv6privateCidrBlocks
        {
            get => _ipv6privateCidrBlocks ?? (_ipv6privateCidrBlocks = new InputList<string>());
            set => _ipv6privateCidrBlocks = value;
        }

        /// <summary>
        /// Whether IPv6 is enabled for the VCN. Default is `false`. If enabled, Oracle will assign the VCN a IPv6 /56 CIDR block. You may skip having Oracle allocate the VCN a IPv6 /56 CIDR block by setting isOracleGuaAllocationEnabled to `false`. For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).  Example: `true`
        /// </summary>
        [Input("isIpv6enabled")]
        public Input<bool>? IsIpv6enabled { get; set; }

        /// <summary>
        /// Specifies whether to skip Oracle allocated IPv6 GUA. By default, Oracle will allocate one GUA of /56 size for an IPv6 enabled VCN.
        /// </summary>
        [Input("isOracleGuaAllocationEnabled")]
        public Input<bool>? IsOracleGuaAllocationEnabled { get; set; }

        public VcnArgs()
        {
        }
        public static new VcnArgs Empty => new VcnArgs();
    }

    public sealed class VcnState : global::Pulumi.ResourceArgs
    {
        [Input("byoipv6cidrBlocks")]
        private InputList<string>? _byoipv6cidrBlocks;

        /// <summary>
        /// The list of BYOIPv6 CIDR blocks required to create a VCN that uses BYOIPv6 ranges.
        /// </summary>
        public InputList<string> Byoipv6cidrBlocks
        {
            get => _byoipv6cidrBlocks ?? (_byoipv6cidrBlocks = new InputList<string>());
            set => _byoipv6cidrBlocks = value;
        }

        [Input("byoipv6cidrDetails")]
        private InputList<Inputs.VcnByoipv6cidrDetailGetArgs>? _byoipv6cidrDetails;

        /// <summary>
        /// The list of BYOIPv6 OCIDs and BYOIPv6 CIDR blocks required to create a VCN that uses BYOIPv6 ranges.
        /// </summary>
        public InputList<Inputs.VcnByoipv6cidrDetailGetArgs> Byoipv6cidrDetails
        {
            get => _byoipv6cidrDetails ?? (_byoipv6cidrDetails = new InputList<Inputs.VcnByoipv6cidrDetailGetArgs>());
            set => _byoipv6cidrDetails = value;
        }

        /// <summary>
        /// **Deprecated.** Do *not* set this value. Use `cidrBlocks` instead. Example: `10.0.0.0/16`
        /// </summary>
        [Input("cidrBlock")]
        public Input<string>? CidrBlock { get; set; }

        [Input("cidrBlocks")]
        private InputList<string>? _cidrBlocks;

        /// <summary>
        /// (Updatable) The list of one or more IPv4 CIDR blocks for the VCN that meet the following criteria:
        /// * The CIDR blocks must be valid.
        /// * They must not overlap with each other or with the on-premises network CIDR block.
        /// * The number of CIDR blocks must not exceed the limit of CIDR blocks allowed per VCN. It is an error to set both cidrBlock and cidrBlocks. Note: cidr_blocks update must be restricted to one operation at a time (either add/remove or modify one single cidr_block) or the operation will be declined. new cidr_block to be added must be placed at the end of the list. Once you migrate to using `cidr_blocks` from `cidr_block`, you will not be able to switch back.
        /// **Important:** Do *not* specify a value for `cidrBlock`. Use this parameter instead.
        /// </summary>
        public InputList<string> CidrBlocks
        {
            get => _cidrBlocks ?? (_cidrBlocks = new InputList<string>());
            set => _cidrBlocks = value;
        }

        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the VCN.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the VCN's default set of DHCP options.
        /// </summary>
        [Input("defaultDhcpOptionsId")]
        public Input<string>? DefaultDhcpOptionsId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the VCN's default route table.
        /// </summary>
        [Input("defaultRouteTableId")]
        public Input<string>? DefaultRouteTableId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the VCN's default security list.
        /// </summary>
        [Input("defaultSecurityListId")]
        public Input<string>? DefaultSecurityListId { get; set; }

        [Input("definedTags")]
        private InputMap<object>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public InputMap<object> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<object>());
            set => _definedTags = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A DNS label for the VCN, used in conjunction with the VNIC's hostname and subnet's DNS label to form a fully qualified domain name (FQDN) for each VNIC within this subnet (for example, `bminstance-1.subnet123.vcn1.oraclevcn.com`). Not required to be unique, but it's a best practice to set unique DNS labels for VCNs in your tenancy. Must be an alphanumeric string that begins with a letter. The value cannot be changed.
        /// </summary>
        [Input("dnsLabel")]
        public Input<string>? DnsLabel { get; set; }

        [Input("freeformTags")]
        private InputMap<object>? _freeformTags;

        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public InputMap<object> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<object>());
            set => _freeformTags = value;
        }

        [Input("ipv6cidrBlocks")]
        private InputList<string>? _ipv6cidrBlocks;

        /// <summary>
        /// For an IPv6-enabled VCN, this is the list of IPv6 CIDR blocks for the VCN's IP address space. The CIDRs are provided by Oracle and the sizes are always /56.
        /// </summary>
        public InputList<string> Ipv6cidrBlocks
        {
            get => _ipv6cidrBlocks ?? (_ipv6cidrBlocks = new InputList<string>());
            set => _ipv6cidrBlocks = value;
        }

        [Input("ipv6privateCidrBlocks")]
        private InputList<string>? _ipv6privateCidrBlocks;

        /// <summary>
        /// The list of one or more ULA or Private IPv6 CIDR blocks for the vcn that meets the following criteria:
        /// * The CIDR blocks must be valid.
        /// * Multiple CIDR blocks must not overlap each other or the on-premises network CIDR block.
        /// * The number of CIDR blocks must not exceed the limit of IPv6 CIDR blocks allowed to a vcn.
        /// </summary>
        public InputList<string> Ipv6privateCidrBlocks
        {
            get => _ipv6privateCidrBlocks ?? (_ipv6privateCidrBlocks = new InputList<string>());
            set => _ipv6privateCidrBlocks = value;
        }

        /// <summary>
        /// Whether IPv6 is enabled for the VCN. Default is `false`. If enabled, Oracle will assign the VCN a IPv6 /56 CIDR block. You may skip having Oracle allocate the VCN a IPv6 /56 CIDR block by setting isOracleGuaAllocationEnabled to `false`. For important details about IPv6 addressing in a VCN, see [IPv6 Addresses](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/ipv6.htm).  Example: `true`
        /// </summary>
        [Input("isIpv6enabled")]
        public Input<bool>? IsIpv6enabled { get; set; }

        /// <summary>
        /// Specifies whether to skip Oracle allocated IPv6 GUA. By default, Oracle will allocate one GUA of /56 size for an IPv6 enabled VCN.
        /// </summary>
        [Input("isOracleGuaAllocationEnabled")]
        public Input<bool>? IsOracleGuaAllocationEnabled { get; set; }

        /// <summary>
        /// The VCN's current state.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The date and time the VCN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The VCN's domain name, which consists of the VCN's DNS label, and the `oraclevcn.com` domain.
        /// </summary>
        [Input("vcnDomainName")]
        public Input<string>? VcnDomainName { get; set; }

        public VcnState()
        {
        }
        public static new VcnState Empty => new VcnState();
    }
}