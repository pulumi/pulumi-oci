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

// This resource provides the Internet Gateway resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new internet gateway for the specified VCN. For more information, see
// [Access to the Internet](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingIGs.htm).
//
// For the purposes of access control, you must provide the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want the Internet
// Gateway to reside. Notice that the internet gateway doesn't have to be in the same compartment as the VCN or
// other Networking Service components. If you're not sure which compartment to use, put the Internet
// Gateway in the same compartment with the VCN. For more information about compartments and access control, see
// [Overview of the IAM Service](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm).
//
// You may optionally specify a *display name* for the internet gateway, otherwise a default is provided. It
// does not have to be unique, and you can change it. Avoid entering confidential information.
//
// For traffic to flow between a subnet and an internet gateway, you must create a route rule accordingly in
// the subnet's route table (for example, 0.0.0.0/0 > internet gateway). See
// [UpdateRouteTable](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/RouteTable/UpdateRouteTable).
//
// You must specify whether the internet gateway is enabled when you create it. If it's disabled, that means no
// traffic will flow to/from the internet even if there's a route rule that enables that traffic. You can later
// use [UpdateInternetGateway](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/InternetGateway/UpdateInternetGateway) to easily disable/enable
// the gateway without changing the route rule.
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
//			_, err := core.NewInternetGateway(ctx, "test_internet_gateway", &core.InternetGatewayArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				VcnId:         pulumi.Any(testVcn.Id),
//				Enabled:       pulumi.Any(internetGatewayEnabled),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(internetGatewayDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				RouteTableId: pulumi.Any(testRouteTable.Id),
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
// InternetGateways can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/internetGateway:InternetGateway test_internet_gateway "id"
// ```
type InternetGateway struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the internet gateway.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled pulumi.BoolPtrOutput `pulumi:"enabled"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the Internet Gateway is using.
	RouteTableId pulumi.StringOutput `pulumi:"routeTableId"`
	// The internet gateway's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway is attached to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewInternetGateway registers a new resource with the given unique name, arguments, and options.
func NewInternetGateway(ctx *pulumi.Context,
	name string, args *InternetGatewayArgs, opts ...pulumi.ResourceOption) (*InternetGateway, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.VcnId == nil {
		return nil, errors.New("invalid value for required argument 'VcnId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource InternetGateway
	err := ctx.RegisterResource("oci:Core/internetGateway:InternetGateway", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetInternetGateway gets an existing InternetGateway resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetInternetGateway(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *InternetGatewayState, opts ...pulumi.ResourceOption) (*InternetGateway, error) {
	var resource InternetGateway
	err := ctx.ReadResource("oci:Core/internetGateway:InternetGateway", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering InternetGateway resources.
type internetGatewayState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the internet gateway.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled *bool `pulumi:"enabled"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the Internet Gateway is using.
	RouteTableId *string `pulumi:"routeTableId"`
	// The internet gateway's current state.
	State *string `pulumi:"state"`
	// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway is attached to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VcnId *string `pulumi:"vcnId"`
}

type InternetGatewayState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the internet gateway.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled pulumi.BoolPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the Internet Gateway is using.
	RouteTableId pulumi.StringPtrInput
	// The internet gateway's current state.
	State pulumi.StringPtrInput
	// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway is attached to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VcnId pulumi.StringPtrInput
}

func (InternetGatewayState) ElementType() reflect.Type {
	return reflect.TypeOf((*internetGatewayState)(nil)).Elem()
}

type internetGatewayArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the internet gateway.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled *bool `pulumi:"enabled"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the Internet Gateway is using.
	RouteTableId *string `pulumi:"routeTableId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway is attached to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VcnId string `pulumi:"vcnId"`
}

// The set of arguments for constructing a InternetGateway resource.
type InternetGatewayArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the internet gateway.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Whether the gateway is enabled upon creation.
	Enabled pulumi.BoolPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the Internet Gateway is using.
	RouteTableId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway is attached to.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	VcnId pulumi.StringInput
}

func (InternetGatewayArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*internetGatewayArgs)(nil)).Elem()
}

type InternetGatewayInput interface {
	pulumi.Input

	ToInternetGatewayOutput() InternetGatewayOutput
	ToInternetGatewayOutputWithContext(ctx context.Context) InternetGatewayOutput
}

func (*InternetGateway) ElementType() reflect.Type {
	return reflect.TypeOf((**InternetGateway)(nil)).Elem()
}

func (i *InternetGateway) ToInternetGatewayOutput() InternetGatewayOutput {
	return i.ToInternetGatewayOutputWithContext(context.Background())
}

func (i *InternetGateway) ToInternetGatewayOutputWithContext(ctx context.Context) InternetGatewayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InternetGatewayOutput)
}

// InternetGatewayArrayInput is an input type that accepts InternetGatewayArray and InternetGatewayArrayOutput values.
// You can construct a concrete instance of `InternetGatewayArrayInput` via:
//
//	InternetGatewayArray{ InternetGatewayArgs{...} }
type InternetGatewayArrayInput interface {
	pulumi.Input

	ToInternetGatewayArrayOutput() InternetGatewayArrayOutput
	ToInternetGatewayArrayOutputWithContext(context.Context) InternetGatewayArrayOutput
}

type InternetGatewayArray []InternetGatewayInput

func (InternetGatewayArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*InternetGateway)(nil)).Elem()
}

func (i InternetGatewayArray) ToInternetGatewayArrayOutput() InternetGatewayArrayOutput {
	return i.ToInternetGatewayArrayOutputWithContext(context.Background())
}

func (i InternetGatewayArray) ToInternetGatewayArrayOutputWithContext(ctx context.Context) InternetGatewayArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InternetGatewayArrayOutput)
}

// InternetGatewayMapInput is an input type that accepts InternetGatewayMap and InternetGatewayMapOutput values.
// You can construct a concrete instance of `InternetGatewayMapInput` via:
//
//	InternetGatewayMap{ "key": InternetGatewayArgs{...} }
type InternetGatewayMapInput interface {
	pulumi.Input

	ToInternetGatewayMapOutput() InternetGatewayMapOutput
	ToInternetGatewayMapOutputWithContext(context.Context) InternetGatewayMapOutput
}

type InternetGatewayMap map[string]InternetGatewayInput

func (InternetGatewayMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*InternetGateway)(nil)).Elem()
}

func (i InternetGatewayMap) ToInternetGatewayMapOutput() InternetGatewayMapOutput {
	return i.ToInternetGatewayMapOutputWithContext(context.Background())
}

func (i InternetGatewayMap) ToInternetGatewayMapOutputWithContext(ctx context.Context) InternetGatewayMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(InternetGatewayMapOutput)
}

type InternetGatewayOutput struct{ *pulumi.OutputState }

func (InternetGatewayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**InternetGateway)(nil)).Elem()
}

func (o InternetGatewayOutput) ToInternetGatewayOutput() InternetGatewayOutput {
	return o
}

func (o InternetGatewayOutput) ToInternetGatewayOutputWithContext(ctx context.Context) InternetGatewayOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the internet gateway.
func (o InternetGatewayOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o InternetGatewayOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o InternetGatewayOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Whether the gateway is enabled upon creation.
func (o InternetGatewayOutput) Enabled() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.BoolPtrOutput { return v.Enabled }).(pulumi.BoolPtrOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o InternetGatewayOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the Internet Gateway is using.
func (o InternetGatewayOutput) RouteTableId() pulumi.StringOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringOutput { return v.RouteTableId }).(pulumi.StringOutput)
}

// The internet gateway's current state.
func (o InternetGatewayOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the internet gateway was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o InternetGatewayOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the Internet Gateway is attached to.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o InternetGatewayOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *InternetGateway) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

type InternetGatewayArrayOutput struct{ *pulumi.OutputState }

func (InternetGatewayArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*InternetGateway)(nil)).Elem()
}

func (o InternetGatewayArrayOutput) ToInternetGatewayArrayOutput() InternetGatewayArrayOutput {
	return o
}

func (o InternetGatewayArrayOutput) ToInternetGatewayArrayOutputWithContext(ctx context.Context) InternetGatewayArrayOutput {
	return o
}

func (o InternetGatewayArrayOutput) Index(i pulumi.IntInput) InternetGatewayOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *InternetGateway {
		return vs[0].([]*InternetGateway)[vs[1].(int)]
	}).(InternetGatewayOutput)
}

type InternetGatewayMapOutput struct{ *pulumi.OutputState }

func (InternetGatewayMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*InternetGateway)(nil)).Elem()
}

func (o InternetGatewayMapOutput) ToInternetGatewayMapOutput() InternetGatewayMapOutput {
	return o
}

func (o InternetGatewayMapOutput) ToInternetGatewayMapOutputWithContext(ctx context.Context) InternetGatewayMapOutput {
	return o
}

func (o InternetGatewayMapOutput) MapIndex(k pulumi.StringInput) InternetGatewayOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *InternetGateway {
		return vs[0].(map[string]*InternetGateway)[vs[1].(string)]
	}).(InternetGatewayOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*InternetGatewayInput)(nil)).Elem(), &InternetGateway{})
	pulumi.RegisterInputType(reflect.TypeOf((*InternetGatewayArrayInput)(nil)).Elem(), InternetGatewayArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*InternetGatewayMapInput)(nil)).Elem(), InternetGatewayMap{})
	pulumi.RegisterOutputType(InternetGatewayOutput{})
	pulumi.RegisterOutputType(InternetGatewayArrayOutput{})
	pulumi.RegisterOutputType(InternetGatewayMapOutput{})
}
