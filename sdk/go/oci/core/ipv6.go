// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Ipv6 resource in Oracle Cloud Infrastructure Core service.
//
// Creates an IPv6 for the specified VNIC.
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
//			_, err := core.NewIpv6(ctx, "test_ipv6", &core.Ipv6Args{
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(ipv6DisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				IpAddress:      pulumi.Any(ipv6IpAddress),
//				Ipv6subnetCidr: pulumi.Any(ipv6Ipv6subnetCidr),
//				Lifetime:       pulumi.Any(ipv6Lifetime),
//				RouteTableId:   pulumi.Any(testRouteTable.Id),
//				SubnetId:       pulumi.Any(testSubnet.Id),
//				VnicId:         pulumi.Any(testVnicAttachment.Id),
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
// Ipv6 can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/ipv6:Ipv6 test_ipv6 "id"
// ```
type Ipv6 struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress pulumi.StringOutput `pulumi:"ipAddress"`
	// State of the IP address. If an IP address is assigned to a VNIC it is ASSIGNED, otherwise it is AVAILABLE.
	IpState pulumi.StringOutput `pulumi:"ipState"`
	// The IPv6 prefix allocated to the subnet. This is required if more than one IPv6 prefix exists on the subnet.
	Ipv6subnetCidr pulumi.StringOutput `pulumi:"ipv6subnetCidr"`
	// (Updatable) Lifetime of the IP address. There are two types of IPv6 IPs:
	// * Ephemeral
	// * Reserved
	Lifetime pulumi.StringOutput `pulumi:"lifetime"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
	RouteTableId pulumi.StringPtrOutput `pulumi:"routeTableId"`
	// The IPv6's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet from which the IPv6 is to be drawn. The IP address, *if supplied*, must be valid for the given subnet, only valid for reserved IPs currently.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VnicId pulumi.StringPtrOutput `pulumi:"vnicId"`
}

// NewIpv6 registers a new resource with the given unique name, arguments, and options.
func NewIpv6(ctx *pulumi.Context,
	name string, args *Ipv6Args, opts ...pulumi.ResourceOption) (*Ipv6, error) {
	if args == nil {
		args = &Ipv6Args{}
	}

	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Ipv6
	err := ctx.RegisterResource("oci:Core/ipv6:Ipv6", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIpv6 gets an existing Ipv6 resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIpv6(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *Ipv6State, opts ...pulumi.ResourceOption) (*Ipv6, error) {
	var resource Ipv6
	err := ctx.ReadResource("oci:Core/ipv6:Ipv6", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Ipv6 resources.
type ipv6State struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress *string `pulumi:"ipAddress"`
	// State of the IP address. If an IP address is assigned to a VNIC it is ASSIGNED, otherwise it is AVAILABLE.
	IpState *string `pulumi:"ipState"`
	// The IPv6 prefix allocated to the subnet. This is required if more than one IPv6 prefix exists on the subnet.
	Ipv6subnetCidr *string `pulumi:"ipv6subnetCidr"`
	// (Updatable) Lifetime of the IP address. There are two types of IPv6 IPs:
	// * Ephemeral
	// * Reserved
	Lifetime *string `pulumi:"lifetime"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
	RouteTableId *string `pulumi:"routeTableId"`
	// The IPv6's current state.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet from which the IPv6 is to be drawn. The IP address, *if supplied*, must be valid for the given subnet, only valid for reserved IPs currently.
	SubnetId *string `pulumi:"subnetId"`
	// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VnicId *string `pulumi:"vnicId"`
}

type Ipv6State struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress pulumi.StringPtrInput
	// State of the IP address. If an IP address is assigned to a VNIC it is ASSIGNED, otherwise it is AVAILABLE.
	IpState pulumi.StringPtrInput
	// The IPv6 prefix allocated to the subnet. This is required if more than one IPv6 prefix exists on the subnet.
	Ipv6subnetCidr pulumi.StringPtrInput
	// (Updatable) Lifetime of the IP address. There are two types of IPv6 IPs:
	// * Ephemeral
	// * Reserved
	Lifetime pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
	RouteTableId pulumi.StringPtrInput
	// The IPv6's current state.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet from which the IPv6 is to be drawn. The IP address, *if supplied*, must be valid for the given subnet, only valid for reserved IPs currently.
	SubnetId pulumi.StringPtrInput
	// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VnicId pulumi.StringPtrInput
}

func (Ipv6State) ElementType() reflect.Type {
	return reflect.TypeOf((*ipv6State)(nil)).Elem()
}

type ipv6Args struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress *string `pulumi:"ipAddress"`
	// The IPv6 prefix allocated to the subnet. This is required if more than one IPv6 prefix exists on the subnet.
	Ipv6subnetCidr *string `pulumi:"ipv6subnetCidr"`
	// (Updatable) Lifetime of the IP address. There are two types of IPv6 IPs:
	// * Ephemeral
	// * Reserved
	Lifetime *string `pulumi:"lifetime"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
	RouteTableId *string `pulumi:"routeTableId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet from which the IPv6 is to be drawn. The IP address, *if supplied*, must be valid for the given subnet, only valid for reserved IPs currently.
	SubnetId *string `pulumi:"subnetId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VnicId *string `pulumi:"vnicId"`
}

// The set of arguments for constructing a Ipv6 resource.
type Ipv6Args struct {
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
	IpAddress pulumi.StringPtrInput
	// The IPv6 prefix allocated to the subnet. This is required if more than one IPv6 prefix exists on the subnet.
	Ipv6subnetCidr pulumi.StringPtrInput
	// (Updatable) Lifetime of the IP address. There are two types of IPv6 IPs:
	// * Ephemeral
	// * Reserved
	Lifetime pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
	RouteTableId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet from which the IPv6 is to be drawn. The IP address, *if supplied*, must be valid for the given subnet, only valid for reserved IPs currently.
	SubnetId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VnicId pulumi.StringPtrInput
}

func (Ipv6Args) ElementType() reflect.Type {
	return reflect.TypeOf((*ipv6Args)(nil)).Elem()
}

type Ipv6Input interface {
	pulumi.Input

	ToIpv6Output() Ipv6Output
	ToIpv6OutputWithContext(ctx context.Context) Ipv6Output
}

func (*Ipv6) ElementType() reflect.Type {
	return reflect.TypeOf((**Ipv6)(nil)).Elem()
}

func (i *Ipv6) ToIpv6Output() Ipv6Output {
	return i.ToIpv6OutputWithContext(context.Background())
}

func (i *Ipv6) ToIpv6OutputWithContext(ctx context.Context) Ipv6Output {
	return pulumi.ToOutputWithContext(ctx, i).(Ipv6Output)
}

// Ipv6ArrayInput is an input type that accepts Ipv6Array and Ipv6ArrayOutput values.
// You can construct a concrete instance of `Ipv6ArrayInput` via:
//
//	Ipv6Array{ Ipv6Args{...} }
type Ipv6ArrayInput interface {
	pulumi.Input

	ToIpv6ArrayOutput() Ipv6ArrayOutput
	ToIpv6ArrayOutputWithContext(context.Context) Ipv6ArrayOutput
}

type Ipv6Array []Ipv6Input

func (Ipv6Array) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Ipv6)(nil)).Elem()
}

func (i Ipv6Array) ToIpv6ArrayOutput() Ipv6ArrayOutput {
	return i.ToIpv6ArrayOutputWithContext(context.Background())
}

func (i Ipv6Array) ToIpv6ArrayOutputWithContext(ctx context.Context) Ipv6ArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(Ipv6ArrayOutput)
}

// Ipv6MapInput is an input type that accepts Ipv6Map and Ipv6MapOutput values.
// You can construct a concrete instance of `Ipv6MapInput` via:
//
//	Ipv6Map{ "key": Ipv6Args{...} }
type Ipv6MapInput interface {
	pulumi.Input

	ToIpv6MapOutput() Ipv6MapOutput
	ToIpv6MapOutputWithContext(context.Context) Ipv6MapOutput
}

type Ipv6Map map[string]Ipv6Input

func (Ipv6Map) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Ipv6)(nil)).Elem()
}

func (i Ipv6Map) ToIpv6MapOutput() Ipv6MapOutput {
	return i.ToIpv6MapOutputWithContext(context.Background())
}

func (i Ipv6Map) ToIpv6MapOutputWithContext(ctx context.Context) Ipv6MapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(Ipv6MapOutput)
}

type Ipv6Output struct{ *pulumi.OutputState }

func (Ipv6Output) ElementType() reflect.Type {
	return reflect.TypeOf((**Ipv6)(nil)).Elem()
}

func (o Ipv6Output) ToIpv6Output() Ipv6Output {
	return o
}

func (o Ipv6Output) ToIpv6OutputWithContext(ctx context.Context) Ipv6Output {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPv6. This is the same as the VNIC's compartment.
func (o Ipv6Output) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o Ipv6Output) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o Ipv6Output) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o Ipv6Output) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// An IPv6 address of your choice. Must be an available IP address within the subnet's CIDR. If you don't specify a value, Oracle automatically assigns an IPv6 address from the subnet. The subnet is the one that contains the VNIC you specify in `vnicId`.  Example: `2001:DB8::`
func (o Ipv6Output) IpAddress() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.IpAddress }).(pulumi.StringOutput)
}

// State of the IP address. If an IP address is assigned to a VNIC it is ASSIGNED, otherwise it is AVAILABLE.
func (o Ipv6Output) IpState() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.IpState }).(pulumi.StringOutput)
}

// The IPv6 prefix allocated to the subnet. This is required if more than one IPv6 prefix exists on the subnet.
func (o Ipv6Output) Ipv6subnetCidr() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.Ipv6subnetCidr }).(pulumi.StringOutput)
}

// (Updatable) Lifetime of the IP address. There are two types of IPv6 IPs:
// * Ephemeral
// * Reserved
func (o Ipv6Output) Lifetime() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.Lifetime }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the IP address or VNIC will use. For more information, see [Source Based Routing](https://docs.oracle.com/iaas/Content/Network/Tasks/managingroutetables.htm#Overview_of_Routing_for_Your_VCN__source_routing).
func (o Ipv6Output) RouteTableId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringPtrOutput { return v.RouteTableId }).(pulumi.StringPtrOutput)
}

// The IPv6's current state.
func (o Ipv6Output) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet from which the IPv6 is to be drawn. The IP address, *if supplied*, must be valid for the given subnet, only valid for reserved IPs currently.
func (o Ipv6Output) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.SubnetId }).(pulumi.StringOutput)
}

// The date and time the IPv6 was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o Ipv6Output) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC to assign the IPv6 to. The IPv6 will be in the VNIC's subnet.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o Ipv6Output) VnicId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v *Ipv6) pulumi.StringPtrOutput { return v.VnicId }).(pulumi.StringPtrOutput)
}

type Ipv6ArrayOutput struct{ *pulumi.OutputState }

func (Ipv6ArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Ipv6)(nil)).Elem()
}

func (o Ipv6ArrayOutput) ToIpv6ArrayOutput() Ipv6ArrayOutput {
	return o
}

func (o Ipv6ArrayOutput) ToIpv6ArrayOutputWithContext(ctx context.Context) Ipv6ArrayOutput {
	return o
}

func (o Ipv6ArrayOutput) Index(i pulumi.IntInput) Ipv6Output {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Ipv6 {
		return vs[0].([]*Ipv6)[vs[1].(int)]
	}).(Ipv6Output)
}

type Ipv6MapOutput struct{ *pulumi.OutputState }

func (Ipv6MapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Ipv6)(nil)).Elem()
}

func (o Ipv6MapOutput) ToIpv6MapOutput() Ipv6MapOutput {
	return o
}

func (o Ipv6MapOutput) ToIpv6MapOutputWithContext(ctx context.Context) Ipv6MapOutput {
	return o
}

func (o Ipv6MapOutput) MapIndex(k pulumi.StringInput) Ipv6Output {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Ipv6 {
		return vs[0].(map[string]*Ipv6)[vs[1].(string)]
	}).(Ipv6Output)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*Ipv6Input)(nil)).Elem(), &Ipv6{})
	pulumi.RegisterInputType(reflect.TypeOf((*Ipv6ArrayInput)(nil)).Elem(), Ipv6Array{})
	pulumi.RegisterInputType(reflect.TypeOf((*Ipv6MapInput)(nil)).Elem(), Ipv6Map{})
	pulumi.RegisterOutputType(Ipv6Output{})
	pulumi.RegisterOutputType(Ipv6ArrayOutput{})
	pulumi.RegisterOutputType(Ipv6MapOutput{})
}
