// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Ip Sec Connection resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new IPSec connection between the specified DRG and CPE with two default static tunnels. For more information, see
// [Site-to-Site VPN Overview](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm).
//
// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the
// IPSec connection to reside. Notice that the IPSec connection doesn't have to be in the same compartment
// as the DRG, CPE, or other Networking Service components. If you're not sure which compartment to
// use, put the IPSec connection in the same compartment as the DRG. For more information about
// compartments and access control, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// You may optionally specify a *display name* for the IPSec connection, otherwise a default is provided.
// It does not have to be unique, and you can change it. Avoid entering confidential information.
//
// After creating the IPSec connection, you need to configure your on-premises router
// with tunnel-specific information. For tunnel status and the required configuration information, see:
//
//   - [IPSecConnectionTunnel](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnectionTunnel/)
//   - [IPSecConnectionTunnelSharedSecret](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnectionTunnelSharedSecret/)
//
// To configure tunnel-specific information, use `Core.IpsecConnectionTunnelManagement` to update the tunnels. If
// you configure at least one tunnel to use static routing, then in the Core.Ipsec request you must provide
// at least one valid static route (you're allowed a maximum of 10). For example: 10.0.0.0/16.
// If you configure both tunnels to use BGP dynamic routing, the static routes will be ignored. However, you must provide a
// static route in `Core.Ipsec` even if you plan to use BGP routing because it defaults to two static tunnels.  For more
// information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
//
// For each tunnel, you need the IP address of Oracle's VPN headend and the shared secret
// (that is, the pre-shared key). For more information, see
// [CPE Configuration](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/configuringCPE.htm).
//
// To configure tunnel-specific information for private ipsec connection over fastconnect, use attribute `tunnelConfiguration`.
// You can provide configuration for maximum of 2 tunnels. You can configure each tunnel with `oracleTunnelIp`,
// `associatedVirtualCircuits` and `drgRouteTableId` at time of creation. These attributes cannot be updated using IPSec
// connection APIs. To update drg route table id, use `Core.DrgAttachmentManagement` resource to update.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.NewIpsec(ctx, "test_ip_sec_connection", &core.IpsecArgs{
//				CompartmentId:          pulumi.Any(compartmentId),
//				CpeId:                  pulumi.Any(testCpe.Id),
//				DrgId:                  pulumi.Any(testDrg.Id),
//				StaticRoutes:           pulumi.Any(ipSecConnectionStaticRoutes),
//				CpeLocalIdentifier:     pulumi.Any(ipSecConnectionCpeLocalIdentifier),
//				CpeLocalIdentifierType: pulumi.Any(ipSecConnectionCpeLocalIdentifierType),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(ipSecConnectionDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			_, err = core.NewIpsec(ctx, "test_ip_sec_connection_over_fc", &core.IpsecArgs{
//				CompartmentId:          pulumi.Any(compartmentId),
//				CpeId:                  pulumi.Any(testCpe.Id),
//				DrgId:                  pulumi.Any(testDrg.Id),
//				StaticRoutes:           pulumi.Any(ipSecConnectionStaticRoutes),
//				CpeLocalIdentifier:     pulumi.Any(ipSecConnectionCpeLocalIdentifier),
//				CpeLocalIdentifierType: pulumi.Any(ipSecConnectionCpeLocalIdentifierType),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(ipSecConnectionDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				TunnelConfigurations: core.IpsecTunnelConfigurationArray{
//					&core.IpsecTunnelConfigurationArgs{
//						OracleTunnelIp: pulumi.String("10.1.5.5"),
//						AssociatedVirtualCircuits: pulumi.StringArray{
//							testIpsecOverFcVirtualCircuit.Id,
//						},
//						DrgRouteTableId: pulumi.Any(testDrgIpsecOverFcRouteTable.Id),
//					},
//					&core.IpsecTunnelConfigurationArgs{
//						OracleTunnelIp: pulumi.String("10.1.7.7"),
//						AssociatedVirtualCircuits: pulumi.StringArray{
//							testIpsecOverFcVirtualCircuit.Id,
//						},
//						DrgRouteTableId: pulumi.Any(testDrgIpsecOverFcRouteTable.Id),
//					},
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// IpSecConnections can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/ipsec:Ipsec test_ip_sec_connection "id"
// ```
type Ipsec struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the IPSec connection.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
	CpeId pulumi.StringOutput `pulumi:"cpeId"`
	// (Updatable) Your identifier for your CPE device. Can be either an IP address or a hostname (specifically, the fully qualified domain name (FQDN)). The type of identifier you provide here must correspond to the value for `cpeLocalIdentifierType`.
	//
	// If you don't provide a value, the `ipAddress` attribute for the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object specified by `cpeId` is used as the `cpeLocalIdentifier`.
	//
	// For information about why you'd provide this value, see [If Your CPE Is Behind a NAT Device](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm#nat).
	//
	// Example IP address: `10.0.3.3`
	//
	// Example hostname: `cpe.example.com`
	CpeLocalIdentifier pulumi.StringOutput `pulumi:"cpeLocalIdentifier"`
	// (Updatable) The type of identifier for your CPE device. The value you provide here must correspond to the value for `cpeLocalIdentifier`.
	CpeLocalIdentifierType pulumi.StringOutput `pulumi:"cpeLocalIdentifierType"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId pulumi.StringOutput `pulumi:"drgId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The IPSec connection's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) Static routes to the CPE. A static route's CIDR must not be a multicast address or class E address.
	//
	// Used for routing a given IPSec tunnel's traffic only if the tunnel is using static routing. If you configure at least one tunnel to use static routing, then you must provide at least one valid static route. If you configure both tunnels to use BGP dynamic routing, you can provide an empty list for the static routes on update. For more information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
	//
	// Example: `10.0.1.0/24`
	StaticRoutes pulumi.StringArrayOutput `pulumi:"staticRoutes"`
	// The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The transport type used for the IPSec connection.
	TransportType pulumi.StringOutput `pulumi:"transportType"`
	// (Non-updatable) Tunnel configuration for private ipsec connection over fastconnect.
	//
	// Example: `tunnelConfiguration {
	// oracleTunnelIp = "10.1.5.5"
	// associatedVirtualCircuits = [oci_core_virtual_circuit.test_ipsec_over_fc_virtual_circuit.id]
	// drgRouteTableId = oci_core_drg_route_table.test_drg_ipsec_over_fc_route_table.id
	// }`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TunnelConfigurations IpsecTunnelConfigurationArrayOutput `pulumi:"tunnelConfigurations"`
}

// NewIpsec registers a new resource with the given unique name, arguments, and options.
func NewIpsec(ctx *pulumi.Context,
	name string, args *IpsecArgs, opts ...pulumi.ResourceOption) (*Ipsec, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.CpeId == nil {
		return nil, errors.New("invalid value for required argument 'CpeId'")
	}
	if args.DrgId == nil {
		return nil, errors.New("invalid value for required argument 'DrgId'")
	}
	if args.StaticRoutes == nil {
		return nil, errors.New("invalid value for required argument 'StaticRoutes'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Ipsec
	err := ctx.RegisterResource("oci:Core/ipsec:Ipsec", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIpsec gets an existing Ipsec resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIpsec(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *IpsecState, opts ...pulumi.ResourceOption) (*Ipsec, error) {
	var resource Ipsec
	err := ctx.ReadResource("oci:Core/ipsec:Ipsec", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Ipsec resources.
type ipsecState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the IPSec connection.
	CompartmentId *string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
	CpeId *string `pulumi:"cpeId"`
	// (Updatable) Your identifier for your CPE device. Can be either an IP address or a hostname (specifically, the fully qualified domain name (FQDN)). The type of identifier you provide here must correspond to the value for `cpeLocalIdentifierType`.
	//
	// If you don't provide a value, the `ipAddress` attribute for the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object specified by `cpeId` is used as the `cpeLocalIdentifier`.
	//
	// For information about why you'd provide this value, see [If Your CPE Is Behind a NAT Device](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm#nat).
	//
	// Example IP address: `10.0.3.3`
	//
	// Example hostname: `cpe.example.com`
	CpeLocalIdentifier *string `pulumi:"cpeLocalIdentifier"`
	// (Updatable) The type of identifier for your CPE device. The value you provide here must correspond to the value for `cpeLocalIdentifier`.
	CpeLocalIdentifierType *string `pulumi:"cpeLocalIdentifierType"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId *string `pulumi:"drgId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The IPSec connection's current state.
	State *string `pulumi:"state"`
	// (Updatable) Static routes to the CPE. A static route's CIDR must not be a multicast address or class E address.
	//
	// Used for routing a given IPSec tunnel's traffic only if the tunnel is using static routing. If you configure at least one tunnel to use static routing, then you must provide at least one valid static route. If you configure both tunnels to use BGP dynamic routing, you can provide an empty list for the static routes on update. For more information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
	//
	// Example: `10.0.1.0/24`
	StaticRoutes []string `pulumi:"staticRoutes"`
	// The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The transport type used for the IPSec connection.
	TransportType *string `pulumi:"transportType"`
	// (Non-updatable) Tunnel configuration for private ipsec connection over fastconnect.
	//
	// Example: `tunnelConfiguration {
	// oracleTunnelIp = "10.1.5.5"
	// associatedVirtualCircuits = [oci_core_virtual_circuit.test_ipsec_over_fc_virtual_circuit.id]
	// drgRouteTableId = oci_core_drg_route_table.test_drg_ipsec_over_fc_route_table.id
	// }`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TunnelConfigurations []IpsecTunnelConfiguration `pulumi:"tunnelConfigurations"`
}

type IpsecState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the IPSec connection.
	CompartmentId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
	CpeId pulumi.StringPtrInput
	// (Updatable) Your identifier for your CPE device. Can be either an IP address or a hostname (specifically, the fully qualified domain name (FQDN)). The type of identifier you provide here must correspond to the value for `cpeLocalIdentifierType`.
	//
	// If you don't provide a value, the `ipAddress` attribute for the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object specified by `cpeId` is used as the `cpeLocalIdentifier`.
	//
	// For information about why you'd provide this value, see [If Your CPE Is Behind a NAT Device](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm#nat).
	//
	// Example IP address: `10.0.3.3`
	//
	// Example hostname: `cpe.example.com`
	CpeLocalIdentifier pulumi.StringPtrInput
	// (Updatable) The type of identifier for your CPE device. The value you provide here must correspond to the value for `cpeLocalIdentifier`.
	CpeLocalIdentifierType pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// The IPSec connection's current state.
	State pulumi.StringPtrInput
	// (Updatable) Static routes to the CPE. A static route's CIDR must not be a multicast address or class E address.
	//
	// Used for routing a given IPSec tunnel's traffic only if the tunnel is using static routing. If you configure at least one tunnel to use static routing, then you must provide at least one valid static route. If you configure both tunnels to use BGP dynamic routing, you can provide an empty list for the static routes on update. For more information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
	//
	// Example: `10.0.1.0/24`
	StaticRoutes pulumi.StringArrayInput
	// The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The transport type used for the IPSec connection.
	TransportType pulumi.StringPtrInput
	// (Non-updatable) Tunnel configuration for private ipsec connection over fastconnect.
	//
	// Example: `tunnelConfiguration {
	// oracleTunnelIp = "10.1.5.5"
	// associatedVirtualCircuits = [oci_core_virtual_circuit.test_ipsec_over_fc_virtual_circuit.id]
	// drgRouteTableId = oci_core_drg_route_table.test_drg_ipsec_over_fc_route_table.id
	// }`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TunnelConfigurations IpsecTunnelConfigurationArrayInput
}

func (IpsecState) ElementType() reflect.Type {
	return reflect.TypeOf((*ipsecState)(nil)).Elem()
}

type ipsecArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the IPSec connection.
	CompartmentId string `pulumi:"compartmentId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
	CpeId string `pulumi:"cpeId"`
	// (Updatable) Your identifier for your CPE device. Can be either an IP address or a hostname (specifically, the fully qualified domain name (FQDN)). The type of identifier you provide here must correspond to the value for `cpeLocalIdentifierType`.
	//
	// If you don't provide a value, the `ipAddress` attribute for the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object specified by `cpeId` is used as the `cpeLocalIdentifier`.
	//
	// For information about why you'd provide this value, see [If Your CPE Is Behind a NAT Device](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm#nat).
	//
	// Example IP address: `10.0.3.3`
	//
	// Example hostname: `cpe.example.com`
	CpeLocalIdentifier *string `pulumi:"cpeLocalIdentifier"`
	// (Updatable) The type of identifier for your CPE device. The value you provide here must correspond to the value for `cpeLocalIdentifier`.
	CpeLocalIdentifierType *string `pulumi:"cpeLocalIdentifierType"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId string `pulumi:"drgId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Static routes to the CPE. A static route's CIDR must not be a multicast address or class E address.
	//
	// Used for routing a given IPSec tunnel's traffic only if the tunnel is using static routing. If you configure at least one tunnel to use static routing, then you must provide at least one valid static route. If you configure both tunnels to use BGP dynamic routing, you can provide an empty list for the static routes on update. For more information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
	//
	// Example: `10.0.1.0/24`
	StaticRoutes []string `pulumi:"staticRoutes"`
	// (Non-updatable) Tunnel configuration for private ipsec connection over fastconnect.
	//
	// Example: `tunnelConfiguration {
	// oracleTunnelIp = "10.1.5.5"
	// associatedVirtualCircuits = [oci_core_virtual_circuit.test_ipsec_over_fc_virtual_circuit.id]
	// drgRouteTableId = oci_core_drg_route_table.test_drg_ipsec_over_fc_route_table.id
	// }`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TunnelConfigurations []IpsecTunnelConfiguration `pulumi:"tunnelConfigurations"`
}

// The set of arguments for constructing a Ipsec resource.
type IpsecArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the IPSec connection.
	CompartmentId pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
	CpeId pulumi.StringInput
	// (Updatable) Your identifier for your CPE device. Can be either an IP address or a hostname (specifically, the fully qualified domain name (FQDN)). The type of identifier you provide here must correspond to the value for `cpeLocalIdentifierType`.
	//
	// If you don't provide a value, the `ipAddress` attribute for the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object specified by `cpeId` is used as the `cpeLocalIdentifier`.
	//
	// For information about why you'd provide this value, see [If Your CPE Is Behind a NAT Device](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm#nat).
	//
	// Example IP address: `10.0.3.3`
	//
	// Example hostname: `cpe.example.com`
	CpeLocalIdentifier pulumi.StringPtrInput
	// (Updatable) The type of identifier for your CPE device. The value you provide here must correspond to the value for `cpeLocalIdentifier`.
	CpeLocalIdentifierType pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
	DrgId pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Static routes to the CPE. A static route's CIDR must not be a multicast address or class E address.
	//
	// Used for routing a given IPSec tunnel's traffic only if the tunnel is using static routing. If you configure at least one tunnel to use static routing, then you must provide at least one valid static route. If you configure both tunnels to use BGP dynamic routing, you can provide an empty list for the static routes on update. For more information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
	//
	// Example: `10.0.1.0/24`
	StaticRoutes pulumi.StringArrayInput
	// (Non-updatable) Tunnel configuration for private ipsec connection over fastconnect.
	//
	// Example: `tunnelConfiguration {
	// oracleTunnelIp = "10.1.5.5"
	// associatedVirtualCircuits = [oci_core_virtual_circuit.test_ipsec_over_fc_virtual_circuit.id]
	// drgRouteTableId = oci_core_drg_route_table.test_drg_ipsec_over_fc_route_table.id
	// }`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TunnelConfigurations IpsecTunnelConfigurationArrayInput
}

func (IpsecArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ipsecArgs)(nil)).Elem()
}

type IpsecInput interface {
	pulumi.Input

	ToIpsecOutput() IpsecOutput
	ToIpsecOutputWithContext(ctx context.Context) IpsecOutput
}

func (*Ipsec) ElementType() reflect.Type {
	return reflect.TypeOf((**Ipsec)(nil)).Elem()
}

func (i *Ipsec) ToIpsecOutput() IpsecOutput {
	return i.ToIpsecOutputWithContext(context.Background())
}

func (i *Ipsec) ToIpsecOutputWithContext(ctx context.Context) IpsecOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IpsecOutput)
}

// IpsecArrayInput is an input type that accepts IpsecArray and IpsecArrayOutput values.
// You can construct a concrete instance of `IpsecArrayInput` via:
//
//	IpsecArray{ IpsecArgs{...} }
type IpsecArrayInput interface {
	pulumi.Input

	ToIpsecArrayOutput() IpsecArrayOutput
	ToIpsecArrayOutputWithContext(context.Context) IpsecArrayOutput
}

type IpsecArray []IpsecInput

func (IpsecArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Ipsec)(nil)).Elem()
}

func (i IpsecArray) ToIpsecArrayOutput() IpsecArrayOutput {
	return i.ToIpsecArrayOutputWithContext(context.Background())
}

func (i IpsecArray) ToIpsecArrayOutputWithContext(ctx context.Context) IpsecArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IpsecArrayOutput)
}

// IpsecMapInput is an input type that accepts IpsecMap and IpsecMapOutput values.
// You can construct a concrete instance of `IpsecMapInput` via:
//
//	IpsecMap{ "key": IpsecArgs{...} }
type IpsecMapInput interface {
	pulumi.Input

	ToIpsecMapOutput() IpsecMapOutput
	ToIpsecMapOutputWithContext(context.Context) IpsecMapOutput
}

type IpsecMap map[string]IpsecInput

func (IpsecMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Ipsec)(nil)).Elem()
}

func (i IpsecMap) ToIpsecMapOutput() IpsecMapOutput {
	return i.ToIpsecMapOutputWithContext(context.Background())
}

func (i IpsecMap) ToIpsecMapOutputWithContext(ctx context.Context) IpsecMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(IpsecMapOutput)
}

type IpsecOutput struct{ *pulumi.OutputState }

func (IpsecOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Ipsec)(nil)).Elem()
}

func (o IpsecOutput) ToIpsecOutput() IpsecOutput {
	return o
}

func (o IpsecOutput) ToIpsecOutputWithContext(ctx context.Context) IpsecOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the IPSec connection.
func (o IpsecOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object.
func (o IpsecOutput) CpeId() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.CpeId }).(pulumi.StringOutput)
}

// (Updatable) Your identifier for your CPE device. Can be either an IP address or a hostname (specifically, the fully qualified domain name (FQDN)). The type of identifier you provide here must correspond to the value for `cpeLocalIdentifierType`.
//
// If you don't provide a value, the `ipAddress` attribute for the [Cpe](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Cpe/) object specified by `cpeId` is used as the `cpeLocalIdentifier`.
//
// For information about why you'd provide this value, see [If Your CPE Is Behind a NAT Device](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/overviewIPsec.htm#nat).
//
// Example IP address: `10.0.3.3`
//
// Example hostname: `cpe.example.com`
func (o IpsecOutput) CpeLocalIdentifier() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.CpeLocalIdentifier }).(pulumi.StringOutput)
}

// (Updatable) The type of identifier for your CPE device. The value you provide here must correspond to the value for `cpeLocalIdentifier`.
func (o IpsecOutput) CpeLocalIdentifierType() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.CpeLocalIdentifierType }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o IpsecOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o IpsecOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG.
func (o IpsecOutput) DrgId() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.DrgId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o IpsecOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The IPSec connection's current state.
func (o IpsecOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) Static routes to the CPE. A static route's CIDR must not be a multicast address or class E address.
//
// Used for routing a given IPSec tunnel's traffic only if the tunnel is using static routing. If you configure at least one tunnel to use static routing, then you must provide at least one valid static route. If you configure both tunnels to use BGP dynamic routing, you can provide an empty list for the static routes on update. For more information, see the important note in [IPSecConnection](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/IPSecConnection/).
//
// Example: `10.0.1.0/24`
func (o IpsecOutput) StaticRoutes() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringArrayOutput { return v.StaticRoutes }).(pulumi.StringArrayOutput)
}

// The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o IpsecOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The transport type used for the IPSec connection.
func (o IpsecOutput) TransportType() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipsec) pulumi.StringOutput { return v.TransportType }).(pulumi.StringOutput)
}

// (Non-updatable) Tunnel configuration for private ipsec connection over fastconnect.
//
// Example: `tunnelConfiguration {
// oracleTunnelIp = "10.1.5.5"
// associatedVirtualCircuits = [oci_core_virtual_circuit.test_ipsec_over_fc_virtual_circuit.id]
// drgRouteTableId = oci_core_drg_route_table.test_drg_ipsec_over_fc_route_table.id
// }`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o IpsecOutput) TunnelConfigurations() IpsecTunnelConfigurationArrayOutput {
	return o.ApplyT(func(v *Ipsec) IpsecTunnelConfigurationArrayOutput { return v.TunnelConfigurations }).(IpsecTunnelConfigurationArrayOutput)
}

type IpsecArrayOutput struct{ *pulumi.OutputState }

func (IpsecArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Ipsec)(nil)).Elem()
}

func (o IpsecArrayOutput) ToIpsecArrayOutput() IpsecArrayOutput {
	return o
}

func (o IpsecArrayOutput) ToIpsecArrayOutputWithContext(ctx context.Context) IpsecArrayOutput {
	return o
}

func (o IpsecArrayOutput) Index(i pulumi.IntInput) IpsecOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Ipsec {
		return vs[0].([]*Ipsec)[vs[1].(int)]
	}).(IpsecOutput)
}

type IpsecMapOutput struct{ *pulumi.OutputState }

func (IpsecMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Ipsec)(nil)).Elem()
}

func (o IpsecMapOutput) ToIpsecMapOutput() IpsecMapOutput {
	return o
}

func (o IpsecMapOutput) ToIpsecMapOutputWithContext(ctx context.Context) IpsecMapOutput {
	return o
}

func (o IpsecMapOutput) MapIndex(k pulumi.StringInput) IpsecOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Ipsec {
		return vs[0].(map[string]*Ipsec)[vs[1].(string)]
	}).(IpsecOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*IpsecInput)(nil)).Elem(), &Ipsec{})
	pulumi.RegisterInputType(reflect.TypeOf((*IpsecArrayInput)(nil)).Elem(), IpsecArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*IpsecMapInput)(nil)).Elem(), IpsecMap{})
	pulumi.RegisterOutputType(IpsecOutput{})
	pulumi.RegisterOutputType(IpsecArrayOutput{})
	pulumi.RegisterOutputType(IpsecMapOutput{})
}
