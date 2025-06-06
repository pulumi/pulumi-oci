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

// This resource provides the Public Ip Pool resource in Oracle Cloud Infrastructure Core service.
//
// Creates a public IP pool.
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
//			_, err := core.NewPublicIpPool(ctx, "test_public_ip_pool", &core.PublicIpPoolArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(publicIpPoolDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
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
// PublicIpPools can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/publicIpPool:PublicIpPool test_public_ip_pool "id"
// ```
type PublicIpPool struct {
	pulumi.CustomResourceState

	// The CIDR blocks added to this pool. This could be all or a portion of a BYOIP CIDR block.
	CidrBlocks pulumi.StringArrayOutput `pulumi:"cidrBlocks"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP pool.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// The public IP pool's current state.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the public IP pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewPublicIpPool registers a new resource with the given unique name, arguments, and options.
func NewPublicIpPool(ctx *pulumi.Context,
	name string, args *PublicIpPoolArgs, opts ...pulumi.ResourceOption) (*PublicIpPool, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource PublicIpPool
	err := ctx.RegisterResource("oci:Core/publicIpPool:PublicIpPool", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPublicIpPool gets an existing PublicIpPool resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPublicIpPool(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PublicIpPoolState, opts ...pulumi.ResourceOption) (*PublicIpPool, error) {
	var resource PublicIpPool
	err := ctx.ReadResource("oci:Core/publicIpPool:PublicIpPool", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PublicIpPool resources.
type publicIpPoolState struct {
	// The CIDR blocks added to this pool. This could be all or a portion of a BYOIP CIDR block.
	CidrBlocks []string `pulumi:"cidrBlocks"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP pool.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The public IP pool's current state.
	State *string `pulumi:"state"`
	// The date and time the public IP pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type PublicIpPoolState struct {
	// The CIDR blocks added to this pool. This could be all or a portion of a BYOIP CIDR block.
	CidrBlocks pulumi.StringArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP pool.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// The public IP pool's current state.
	State pulumi.StringPtrInput
	// The date and time the public IP pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (PublicIpPoolState) ElementType() reflect.Type {
	return reflect.TypeOf((*publicIpPoolState)(nil)).Elem()
}

type publicIpPoolArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP pool.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a PublicIpPool resource.
type PublicIpPoolArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP pool.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (PublicIpPoolArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*publicIpPoolArgs)(nil)).Elem()
}

type PublicIpPoolInput interface {
	pulumi.Input

	ToPublicIpPoolOutput() PublicIpPoolOutput
	ToPublicIpPoolOutputWithContext(ctx context.Context) PublicIpPoolOutput
}

func (*PublicIpPool) ElementType() reflect.Type {
	return reflect.TypeOf((**PublicIpPool)(nil)).Elem()
}

func (i *PublicIpPool) ToPublicIpPoolOutput() PublicIpPoolOutput {
	return i.ToPublicIpPoolOutputWithContext(context.Background())
}

func (i *PublicIpPool) ToPublicIpPoolOutputWithContext(ctx context.Context) PublicIpPoolOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PublicIpPoolOutput)
}

// PublicIpPoolArrayInput is an input type that accepts PublicIpPoolArray and PublicIpPoolArrayOutput values.
// You can construct a concrete instance of `PublicIpPoolArrayInput` via:
//
//	PublicIpPoolArray{ PublicIpPoolArgs{...} }
type PublicIpPoolArrayInput interface {
	pulumi.Input

	ToPublicIpPoolArrayOutput() PublicIpPoolArrayOutput
	ToPublicIpPoolArrayOutputWithContext(context.Context) PublicIpPoolArrayOutput
}

type PublicIpPoolArray []PublicIpPoolInput

func (PublicIpPoolArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*PublicIpPool)(nil)).Elem()
}

func (i PublicIpPoolArray) ToPublicIpPoolArrayOutput() PublicIpPoolArrayOutput {
	return i.ToPublicIpPoolArrayOutputWithContext(context.Background())
}

func (i PublicIpPoolArray) ToPublicIpPoolArrayOutputWithContext(ctx context.Context) PublicIpPoolArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PublicIpPoolArrayOutput)
}

// PublicIpPoolMapInput is an input type that accepts PublicIpPoolMap and PublicIpPoolMapOutput values.
// You can construct a concrete instance of `PublicIpPoolMapInput` via:
//
//	PublicIpPoolMap{ "key": PublicIpPoolArgs{...} }
type PublicIpPoolMapInput interface {
	pulumi.Input

	ToPublicIpPoolMapOutput() PublicIpPoolMapOutput
	ToPublicIpPoolMapOutputWithContext(context.Context) PublicIpPoolMapOutput
}

type PublicIpPoolMap map[string]PublicIpPoolInput

func (PublicIpPoolMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*PublicIpPool)(nil)).Elem()
}

func (i PublicIpPoolMap) ToPublicIpPoolMapOutput() PublicIpPoolMapOutput {
	return i.ToPublicIpPoolMapOutputWithContext(context.Background())
}

func (i PublicIpPoolMap) ToPublicIpPoolMapOutputWithContext(ctx context.Context) PublicIpPoolMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(PublicIpPoolMapOutput)
}

type PublicIpPoolOutput struct{ *pulumi.OutputState }

func (PublicIpPoolOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**PublicIpPool)(nil)).Elem()
}

func (o PublicIpPoolOutput) ToPublicIpPoolOutput() PublicIpPoolOutput {
	return o
}

func (o PublicIpPoolOutput) ToPublicIpPoolOutputWithContext(ctx context.Context) PublicIpPoolOutput {
	return o
}

// The CIDR blocks added to this pool. This could be all or a portion of a BYOIP CIDR block.
func (o PublicIpPoolOutput) CidrBlocks() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringArrayOutput { return v.CidrBlocks }).(pulumi.StringArrayOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the public IP pool.
func (o PublicIpPoolOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o PublicIpPoolOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o PublicIpPoolOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o PublicIpPoolOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The public IP pool's current state.
func (o PublicIpPoolOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the public IP pool was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o PublicIpPoolOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *PublicIpPool) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type PublicIpPoolArrayOutput struct{ *pulumi.OutputState }

func (PublicIpPoolArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*PublicIpPool)(nil)).Elem()
}

func (o PublicIpPoolArrayOutput) ToPublicIpPoolArrayOutput() PublicIpPoolArrayOutput {
	return o
}

func (o PublicIpPoolArrayOutput) ToPublicIpPoolArrayOutputWithContext(ctx context.Context) PublicIpPoolArrayOutput {
	return o
}

func (o PublicIpPoolArrayOutput) Index(i pulumi.IntInput) PublicIpPoolOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *PublicIpPool {
		return vs[0].([]*PublicIpPool)[vs[1].(int)]
	}).(PublicIpPoolOutput)
}

type PublicIpPoolMapOutput struct{ *pulumi.OutputState }

func (PublicIpPoolMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*PublicIpPool)(nil)).Elem()
}

func (o PublicIpPoolMapOutput) ToPublicIpPoolMapOutput() PublicIpPoolMapOutput {
	return o
}

func (o PublicIpPoolMapOutput) ToPublicIpPoolMapOutputWithContext(ctx context.Context) PublicIpPoolMapOutput {
	return o
}

func (o PublicIpPoolMapOutput) MapIndex(k pulumi.StringInput) PublicIpPoolOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *PublicIpPool {
		return vs[0].(map[string]*PublicIpPool)[vs[1].(string)]
	}).(PublicIpPoolOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*PublicIpPoolInput)(nil)).Elem(), &PublicIpPool{})
	pulumi.RegisterInputType(reflect.TypeOf((*PublicIpPoolArrayInput)(nil)).Elem(), PublicIpPoolArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*PublicIpPoolMapInput)(nil)).Elem(), PublicIpPoolMap{})
	pulumi.RegisterOutputType(PublicIpPoolOutput{})
	pulumi.RegisterOutputType(PublicIpPoolArrayOutput{})
	pulumi.RegisterOutputType(PublicIpPoolMapOutput{})
}
