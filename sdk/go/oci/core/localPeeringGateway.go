// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Local Peering Gateway resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new local peering gateway (LPG) for the specified VCN.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Core.NewLocalPeeringGateway(ctx, "testLocalPeeringGateway", &Core.LocalPeeringGatewayArgs{
//				CompartmentId: pulumi.Any(_var.Compartment_id),
//				VcnId:         pulumi.Any(oci_core_vcn.Test_vcn.Id),
//				DefinedTags: pulumi.AnyMap{
//					"Operations.CostCenter": pulumi.Any("42"),
//				},
//				DisplayName: pulumi.Any(_var.Local_peering_gateway_display_name),
//				FreeformTags: pulumi.AnyMap{
//					"Department": pulumi.Any("Finance"),
//				},
//				PeerId:       pulumi.Any(oci_core_local_peering_gateway.Test_local_peering_gateway2.Id),
//				RouteTableId: pulumi.Any(oci_core_route_table.Test_route_table.Id),
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
// LocalPeeringGateways can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:Core/localPeeringGateway:LocalPeeringGateway test_local_peering_gateway "id"
//
// ```
type LocalPeeringGateway struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
	IsCrossTenancyPeering pulumi.BoolOutput `pulumi:"isCrossTenancyPeering"`
	// The smallest aggregate CIDR that contains all the CIDR routes advertised by the VCN at the other end of the peering from this LPG. See `peerAdvertisedCidrDetails` for the individual CIDRs. The value is `null` if the LPG is not peered.  Example: `192.168.0.0/16`, or if aggregated with `172.16.0.0/24` then `128.0.0.0/1`
	PeerAdvertisedCidr pulumi.StringOutput `pulumi:"peerAdvertisedCidr"`
	// The specific ranges of IP addresses available on or via the VCN at the other end of the peering from this LPG. The value is `null` if the LPG is not peered. You can use these as destination CIDRs for route rules to route a subnet's traffic to this LPG.  Example: [`192.168.0.0/16`, `172.16.0.0/24`]
	PeerAdvertisedCidrDetails pulumi.StringArrayOutput `pulumi:"peerAdvertisedCidrDetails"`
	// The OCID of the LPG you want to peer with. Specifying a peerId connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor's compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
	PeerId pulumi.StringOutput `pulumi:"peerId"`
	// Whether the LPG is peered with another LPG. `NEW` means the LPG has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the LPG at the other end of the peering has been deleted.
	PeeringStatus pulumi.StringOutput `pulumi:"peeringStatus"`
	// Additional information regarding the peering status, if applicable.
	PeeringStatusDetails pulumi.StringOutput `pulumi:"peeringStatusDetails"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
	RouteTableId pulumi.StringOutput `pulumi:"routeTableId"`
	// The LPG's current lifecycle state.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the LPG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewLocalPeeringGateway registers a new resource with the given unique name, arguments, and options.
func NewLocalPeeringGateway(ctx *pulumi.Context,
	name string, args *LocalPeeringGatewayArgs, opts ...pulumi.ResourceOption) (*LocalPeeringGateway, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.VcnId == nil {
		return nil, errors.New("invalid value for required argument 'VcnId'")
	}
	var resource LocalPeeringGateway
	err := ctx.RegisterResource("oci:Core/localPeeringGateway:LocalPeeringGateway", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLocalPeeringGateway gets an existing LocalPeeringGateway resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLocalPeeringGateway(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LocalPeeringGatewayState, opts ...pulumi.ResourceOption) (*LocalPeeringGateway, error) {
	var resource LocalPeeringGateway
	err := ctx.ReadResource("oci:Core/localPeeringGateway:LocalPeeringGateway", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LocalPeeringGateway resources.
type localPeeringGatewayState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
	IsCrossTenancyPeering *bool `pulumi:"isCrossTenancyPeering"`
	// The smallest aggregate CIDR that contains all the CIDR routes advertised by the VCN at the other end of the peering from this LPG. See `peerAdvertisedCidrDetails` for the individual CIDRs. The value is `null` if the LPG is not peered.  Example: `192.168.0.0/16`, or if aggregated with `172.16.0.0/24` then `128.0.0.0/1`
	PeerAdvertisedCidr *string `pulumi:"peerAdvertisedCidr"`
	// The specific ranges of IP addresses available on or via the VCN at the other end of the peering from this LPG. The value is `null` if the LPG is not peered. You can use these as destination CIDRs for route rules to route a subnet's traffic to this LPG.  Example: [`192.168.0.0/16`, `172.16.0.0/24`]
	PeerAdvertisedCidrDetails []string `pulumi:"peerAdvertisedCidrDetails"`
	// The OCID of the LPG you want to peer with. Specifying a peerId connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor's compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
	PeerId *string `pulumi:"peerId"`
	// Whether the LPG is peered with another LPG. `NEW` means the LPG has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the LPG at the other end of the peering has been deleted.
	PeeringStatus *string `pulumi:"peeringStatus"`
	// Additional information regarding the peering status, if applicable.
	PeeringStatusDetails *string `pulumi:"peeringStatusDetails"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
	RouteTableId *string `pulumi:"routeTableId"`
	// The LPG's current lifecycle state.
	State *string `pulumi:"state"`
	// The date and time the LPG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
	VcnId *string `pulumi:"vcnId"`
}

type LocalPeeringGatewayState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
	IsCrossTenancyPeering pulumi.BoolPtrInput
	// The smallest aggregate CIDR that contains all the CIDR routes advertised by the VCN at the other end of the peering from this LPG. See `peerAdvertisedCidrDetails` for the individual CIDRs. The value is `null` if the LPG is not peered.  Example: `192.168.0.0/16`, or if aggregated with `172.16.0.0/24` then `128.0.0.0/1`
	PeerAdvertisedCidr pulumi.StringPtrInput
	// The specific ranges of IP addresses available on or via the VCN at the other end of the peering from this LPG. The value is `null` if the LPG is not peered. You can use these as destination CIDRs for route rules to route a subnet's traffic to this LPG.  Example: [`192.168.0.0/16`, `172.16.0.0/24`]
	PeerAdvertisedCidrDetails pulumi.StringArrayInput
	// The OCID of the LPG you want to peer with. Specifying a peerId connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor's compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
	PeerId pulumi.StringPtrInput
	// Whether the LPG is peered with another LPG. `NEW` means the LPG has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the LPG at the other end of the peering has been deleted.
	PeeringStatus pulumi.StringPtrInput
	// Additional information regarding the peering status, if applicable.
	PeeringStatusDetails pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
	RouteTableId pulumi.StringPtrInput
	// The LPG's current lifecycle state.
	State pulumi.StringPtrInput
	// The date and time the LPG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
	VcnId pulumi.StringPtrInput
}

func (LocalPeeringGatewayState) ElementType() reflect.Type {
	return reflect.TypeOf((*localPeeringGatewayState)(nil)).Elem()
}

type localPeeringGatewayArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the LPG you want to peer with. Specifying a peerId connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor's compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
	PeerId *string `pulumi:"peerId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
	RouteTableId *string `pulumi:"routeTableId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
	VcnId string `pulumi:"vcnId"`
}

// The set of arguments for constructing a LocalPeeringGateway resource.
type LocalPeeringGatewayArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The OCID of the LPG you want to peer with. Specifying a peerId connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor's compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
	PeerId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
	RouteTableId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
	VcnId pulumi.StringInput
}

func (LocalPeeringGatewayArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*localPeeringGatewayArgs)(nil)).Elem()
}

type LocalPeeringGatewayInput interface {
	pulumi.Input

	ToLocalPeeringGatewayOutput() LocalPeeringGatewayOutput
	ToLocalPeeringGatewayOutputWithContext(ctx context.Context) LocalPeeringGatewayOutput
}

func (*LocalPeeringGateway) ElementType() reflect.Type {
	return reflect.TypeOf((**LocalPeeringGateway)(nil)).Elem()
}

func (i *LocalPeeringGateway) ToLocalPeeringGatewayOutput() LocalPeeringGatewayOutput {
	return i.ToLocalPeeringGatewayOutputWithContext(context.Background())
}

func (i *LocalPeeringGateway) ToLocalPeeringGatewayOutputWithContext(ctx context.Context) LocalPeeringGatewayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LocalPeeringGatewayOutput)
}

// LocalPeeringGatewayArrayInput is an input type that accepts LocalPeeringGatewayArray and LocalPeeringGatewayArrayOutput values.
// You can construct a concrete instance of `LocalPeeringGatewayArrayInput` via:
//
//	LocalPeeringGatewayArray{ LocalPeeringGatewayArgs{...} }
type LocalPeeringGatewayArrayInput interface {
	pulumi.Input

	ToLocalPeeringGatewayArrayOutput() LocalPeeringGatewayArrayOutput
	ToLocalPeeringGatewayArrayOutputWithContext(context.Context) LocalPeeringGatewayArrayOutput
}

type LocalPeeringGatewayArray []LocalPeeringGatewayInput

func (LocalPeeringGatewayArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LocalPeeringGateway)(nil)).Elem()
}

func (i LocalPeeringGatewayArray) ToLocalPeeringGatewayArrayOutput() LocalPeeringGatewayArrayOutput {
	return i.ToLocalPeeringGatewayArrayOutputWithContext(context.Background())
}

func (i LocalPeeringGatewayArray) ToLocalPeeringGatewayArrayOutputWithContext(ctx context.Context) LocalPeeringGatewayArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LocalPeeringGatewayArrayOutput)
}

// LocalPeeringGatewayMapInput is an input type that accepts LocalPeeringGatewayMap and LocalPeeringGatewayMapOutput values.
// You can construct a concrete instance of `LocalPeeringGatewayMapInput` via:
//
//	LocalPeeringGatewayMap{ "key": LocalPeeringGatewayArgs{...} }
type LocalPeeringGatewayMapInput interface {
	pulumi.Input

	ToLocalPeeringGatewayMapOutput() LocalPeeringGatewayMapOutput
	ToLocalPeeringGatewayMapOutputWithContext(context.Context) LocalPeeringGatewayMapOutput
}

type LocalPeeringGatewayMap map[string]LocalPeeringGatewayInput

func (LocalPeeringGatewayMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LocalPeeringGateway)(nil)).Elem()
}

func (i LocalPeeringGatewayMap) ToLocalPeeringGatewayMapOutput() LocalPeeringGatewayMapOutput {
	return i.ToLocalPeeringGatewayMapOutputWithContext(context.Background())
}

func (i LocalPeeringGatewayMap) ToLocalPeeringGatewayMapOutputWithContext(ctx context.Context) LocalPeeringGatewayMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LocalPeeringGatewayMapOutput)
}

type LocalPeeringGatewayOutput struct{ *pulumi.OutputState }

func (LocalPeeringGatewayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LocalPeeringGateway)(nil)).Elem()
}

func (o LocalPeeringGatewayOutput) ToLocalPeeringGatewayOutput() LocalPeeringGatewayOutput {
	return o
}

func (o LocalPeeringGatewayOutput) ToLocalPeeringGatewayOutputWithContext(ctx context.Context) LocalPeeringGatewayOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the local peering gateway (LPG).
func (o LocalPeeringGatewayOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LocalPeeringGatewayOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LocalPeeringGatewayOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LocalPeeringGatewayOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
func (o LocalPeeringGatewayOutput) IsCrossTenancyPeering() pulumi.BoolOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.BoolOutput { return v.IsCrossTenancyPeering }).(pulumi.BoolOutput)
}

// The smallest aggregate CIDR that contains all the CIDR routes advertised by the VCN at the other end of the peering from this LPG. See `peerAdvertisedCidrDetails` for the individual CIDRs. The value is `null` if the LPG is not peered.  Example: `192.168.0.0/16`, or if aggregated with `172.16.0.0/24` then `128.0.0.0/1`
func (o LocalPeeringGatewayOutput) PeerAdvertisedCidr() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.PeerAdvertisedCidr }).(pulumi.StringOutput)
}

// The specific ranges of IP addresses available on or via the VCN at the other end of the peering from this LPG. The value is `null` if the LPG is not peered. You can use these as destination CIDRs for route rules to route a subnet's traffic to this LPG.  Example: [`192.168.0.0/16`, `172.16.0.0/24`]
func (o LocalPeeringGatewayOutput) PeerAdvertisedCidrDetails() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringArrayOutput { return v.PeerAdvertisedCidrDetails }).(pulumi.StringArrayOutput)
}

// The OCID of the LPG you want to peer with. Specifying a peerId connects this local peering gateway (LPG) to another one in the same region. This operation must be called by the VCN administrator who is designated as the *requestor* in the peering relationship. The *acceptor* must implement an Identity and Access Management (IAM) policy that gives the requestor permission to connect to LPGs in the acceptor's compartment. Without that permission, this operation will fail. For more information, see [VCN Peering](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/VCNpeering.htm).
func (o LocalPeeringGatewayOutput) PeerId() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.PeerId }).(pulumi.StringOutput)
}

// Whether the LPG is peered with another LPG. `NEW` means the LPG has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the LPG at the other end of the peering has been deleted.
func (o LocalPeeringGatewayOutput) PeeringStatus() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.PeeringStatus }).(pulumi.StringOutput)
}

// Additional information regarding the peering status, if applicable.
func (o LocalPeeringGatewayOutput) PeeringStatusDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.PeeringStatusDetails }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the LPG will use.
func (o LocalPeeringGatewayOutput) RouteTableId() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.RouteTableId }).(pulumi.StringOutput)
}

// The LPG's current lifecycle state.
func (o LocalPeeringGatewayOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the LPG was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LocalPeeringGatewayOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the LPG belongs to.
func (o LocalPeeringGatewayOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *LocalPeeringGateway) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

type LocalPeeringGatewayArrayOutput struct{ *pulumi.OutputState }

func (LocalPeeringGatewayArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LocalPeeringGateway)(nil)).Elem()
}

func (o LocalPeeringGatewayArrayOutput) ToLocalPeeringGatewayArrayOutput() LocalPeeringGatewayArrayOutput {
	return o
}

func (o LocalPeeringGatewayArrayOutput) ToLocalPeeringGatewayArrayOutputWithContext(ctx context.Context) LocalPeeringGatewayArrayOutput {
	return o
}

func (o LocalPeeringGatewayArrayOutput) Index(i pulumi.IntInput) LocalPeeringGatewayOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *LocalPeeringGateway {
		return vs[0].([]*LocalPeeringGateway)[vs[1].(int)]
	}).(LocalPeeringGatewayOutput)
}

type LocalPeeringGatewayMapOutput struct{ *pulumi.OutputState }

func (LocalPeeringGatewayMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LocalPeeringGateway)(nil)).Elem()
}

func (o LocalPeeringGatewayMapOutput) ToLocalPeeringGatewayMapOutput() LocalPeeringGatewayMapOutput {
	return o
}

func (o LocalPeeringGatewayMapOutput) ToLocalPeeringGatewayMapOutputWithContext(ctx context.Context) LocalPeeringGatewayMapOutput {
	return o
}

func (o LocalPeeringGatewayMapOutput) MapIndex(k pulumi.StringInput) LocalPeeringGatewayOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *LocalPeeringGateway {
		return vs[0].(map[string]*LocalPeeringGateway)[vs[1].(string)]
	}).(LocalPeeringGatewayOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*LocalPeeringGatewayInput)(nil)).Elem(), &LocalPeeringGateway{})
	pulumi.RegisterInputType(reflect.TypeOf((*LocalPeeringGatewayArrayInput)(nil)).Elem(), LocalPeeringGatewayArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*LocalPeeringGatewayMapInput)(nil)).Elem(), LocalPeeringGatewayMap{})
	pulumi.RegisterOutputType(LocalPeeringGatewayOutput{})
	pulumi.RegisterOutputType(LocalPeeringGatewayArrayOutput{})
	pulumi.RegisterOutputType(LocalPeeringGatewayMapOutput{})
}