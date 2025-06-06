// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package capacitymanagement

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Occ Customer Group Occ Customer resource in Oracle Cloud Infrastructure Capacity Management service.
//
// Create customer.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/capacitymanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := capacitymanagement.NewOccCustomerGroupOccCustomer(ctx, "test_occ_customer_group_occ_customer", &capacitymanagement.OccCustomerGroupOccCustomerArgs{
//				DisplayName:        pulumi.Any(occCustomerGroupOccCustomerDisplayName),
//				OccCustomerGroupId: pulumi.Any(testOccCustomerGroup.Id),
//				TenancyId:          pulumi.Any(testTenancy.Id),
//				Description:        pulumi.Any(occCustomerGroupOccCustomerDescription),
//				Status:             pulumi.Any(occCustomerGroupOccCustomerStatus),
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
// OccCustomerGroupOccCustomers can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CapacityManagement/occCustomerGroupOccCustomer:OccCustomerGroupOccCustomer test_occ_customer_group_occ_customer "id"
// ```
type OccCustomerGroupOccCustomer struct {
	pulumi.CustomResourceState

	// (Updatable) The description about the customer group.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name for the customer.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The OCID of the customer group.
	OccCustomerGroupId pulumi.StringOutput `pulumi:"occCustomerGroupId"`
	// (Updatable) To determine whether the customer is enabled/disabled.
	Status pulumi.StringOutput `pulumi:"status"`
	// The OCID of the tenancy belonging to the customer.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TenancyId pulumi.StringOutput `pulumi:"tenancyId"`
}

// NewOccCustomerGroupOccCustomer registers a new resource with the given unique name, arguments, and options.
func NewOccCustomerGroupOccCustomer(ctx *pulumi.Context,
	name string, args *OccCustomerGroupOccCustomerArgs, opts ...pulumi.ResourceOption) (*OccCustomerGroupOccCustomer, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	if args.OccCustomerGroupId == nil {
		return nil, errors.New("invalid value for required argument 'OccCustomerGroupId'")
	}
	if args.TenancyId == nil {
		return nil, errors.New("invalid value for required argument 'TenancyId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource OccCustomerGroupOccCustomer
	err := ctx.RegisterResource("oci:CapacityManagement/occCustomerGroupOccCustomer:OccCustomerGroupOccCustomer", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetOccCustomerGroupOccCustomer gets an existing OccCustomerGroupOccCustomer resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetOccCustomerGroupOccCustomer(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *OccCustomerGroupOccCustomerState, opts ...pulumi.ResourceOption) (*OccCustomerGroupOccCustomer, error) {
	var resource OccCustomerGroupOccCustomer
	err := ctx.ReadResource("oci:CapacityManagement/occCustomerGroupOccCustomer:OccCustomerGroupOccCustomer", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering OccCustomerGroupOccCustomer resources.
type occCustomerGroupOccCustomerState struct {
	// (Updatable) The description about the customer group.
	Description *string `pulumi:"description"`
	// (Updatable) The display name for the customer.
	DisplayName *string `pulumi:"displayName"`
	// The OCID of the customer group.
	OccCustomerGroupId *string `pulumi:"occCustomerGroupId"`
	// (Updatable) To determine whether the customer is enabled/disabled.
	Status *string `pulumi:"status"`
	// The OCID of the tenancy belonging to the customer.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TenancyId *string `pulumi:"tenancyId"`
}

type OccCustomerGroupOccCustomerState struct {
	// (Updatable) The description about the customer group.
	Description pulumi.StringPtrInput
	// (Updatable) The display name for the customer.
	DisplayName pulumi.StringPtrInput
	// The OCID of the customer group.
	OccCustomerGroupId pulumi.StringPtrInput
	// (Updatable) To determine whether the customer is enabled/disabled.
	Status pulumi.StringPtrInput
	// The OCID of the tenancy belonging to the customer.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TenancyId pulumi.StringPtrInput
}

func (OccCustomerGroupOccCustomerState) ElementType() reflect.Type {
	return reflect.TypeOf((*occCustomerGroupOccCustomerState)(nil)).Elem()
}

type occCustomerGroupOccCustomerArgs struct {
	// (Updatable) The description about the customer group.
	Description *string `pulumi:"description"`
	// (Updatable) The display name for the customer.
	DisplayName string `pulumi:"displayName"`
	// The OCID of the customer group.
	OccCustomerGroupId string `pulumi:"occCustomerGroupId"`
	// (Updatable) To determine whether the customer is enabled/disabled.
	Status *string `pulumi:"status"`
	// The OCID of the tenancy belonging to the customer.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TenancyId string `pulumi:"tenancyId"`
}

// The set of arguments for constructing a OccCustomerGroupOccCustomer resource.
type OccCustomerGroupOccCustomerArgs struct {
	// (Updatable) The description about the customer group.
	Description pulumi.StringPtrInput
	// (Updatable) The display name for the customer.
	DisplayName pulumi.StringInput
	// The OCID of the customer group.
	OccCustomerGroupId pulumi.StringInput
	// (Updatable) To determine whether the customer is enabled/disabled.
	Status pulumi.StringPtrInput
	// The OCID of the tenancy belonging to the customer.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	TenancyId pulumi.StringInput
}

func (OccCustomerGroupOccCustomerArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*occCustomerGroupOccCustomerArgs)(nil)).Elem()
}

type OccCustomerGroupOccCustomerInput interface {
	pulumi.Input

	ToOccCustomerGroupOccCustomerOutput() OccCustomerGroupOccCustomerOutput
	ToOccCustomerGroupOccCustomerOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerOutput
}

func (*OccCustomerGroupOccCustomer) ElementType() reflect.Type {
	return reflect.TypeOf((**OccCustomerGroupOccCustomer)(nil)).Elem()
}

func (i *OccCustomerGroupOccCustomer) ToOccCustomerGroupOccCustomerOutput() OccCustomerGroupOccCustomerOutput {
	return i.ToOccCustomerGroupOccCustomerOutputWithContext(context.Background())
}

func (i *OccCustomerGroupOccCustomer) ToOccCustomerGroupOccCustomerOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccCustomerGroupOccCustomerOutput)
}

// OccCustomerGroupOccCustomerArrayInput is an input type that accepts OccCustomerGroupOccCustomerArray and OccCustomerGroupOccCustomerArrayOutput values.
// You can construct a concrete instance of `OccCustomerGroupOccCustomerArrayInput` via:
//
//	OccCustomerGroupOccCustomerArray{ OccCustomerGroupOccCustomerArgs{...} }
type OccCustomerGroupOccCustomerArrayInput interface {
	pulumi.Input

	ToOccCustomerGroupOccCustomerArrayOutput() OccCustomerGroupOccCustomerArrayOutput
	ToOccCustomerGroupOccCustomerArrayOutputWithContext(context.Context) OccCustomerGroupOccCustomerArrayOutput
}

type OccCustomerGroupOccCustomerArray []OccCustomerGroupOccCustomerInput

func (OccCustomerGroupOccCustomerArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OccCustomerGroupOccCustomer)(nil)).Elem()
}

func (i OccCustomerGroupOccCustomerArray) ToOccCustomerGroupOccCustomerArrayOutput() OccCustomerGroupOccCustomerArrayOutput {
	return i.ToOccCustomerGroupOccCustomerArrayOutputWithContext(context.Background())
}

func (i OccCustomerGroupOccCustomerArray) ToOccCustomerGroupOccCustomerArrayOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccCustomerGroupOccCustomerArrayOutput)
}

// OccCustomerGroupOccCustomerMapInput is an input type that accepts OccCustomerGroupOccCustomerMap and OccCustomerGroupOccCustomerMapOutput values.
// You can construct a concrete instance of `OccCustomerGroupOccCustomerMapInput` via:
//
//	OccCustomerGroupOccCustomerMap{ "key": OccCustomerGroupOccCustomerArgs{...} }
type OccCustomerGroupOccCustomerMapInput interface {
	pulumi.Input

	ToOccCustomerGroupOccCustomerMapOutput() OccCustomerGroupOccCustomerMapOutput
	ToOccCustomerGroupOccCustomerMapOutputWithContext(context.Context) OccCustomerGroupOccCustomerMapOutput
}

type OccCustomerGroupOccCustomerMap map[string]OccCustomerGroupOccCustomerInput

func (OccCustomerGroupOccCustomerMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OccCustomerGroupOccCustomer)(nil)).Elem()
}

func (i OccCustomerGroupOccCustomerMap) ToOccCustomerGroupOccCustomerMapOutput() OccCustomerGroupOccCustomerMapOutput {
	return i.ToOccCustomerGroupOccCustomerMapOutputWithContext(context.Background())
}

func (i OccCustomerGroupOccCustomerMap) ToOccCustomerGroupOccCustomerMapOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OccCustomerGroupOccCustomerMapOutput)
}

type OccCustomerGroupOccCustomerOutput struct{ *pulumi.OutputState }

func (OccCustomerGroupOccCustomerOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**OccCustomerGroupOccCustomer)(nil)).Elem()
}

func (o OccCustomerGroupOccCustomerOutput) ToOccCustomerGroupOccCustomerOutput() OccCustomerGroupOccCustomerOutput {
	return o
}

func (o OccCustomerGroupOccCustomerOutput) ToOccCustomerGroupOccCustomerOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerOutput {
	return o
}

// (Updatable) The description about the customer group.
func (o OccCustomerGroupOccCustomerOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *OccCustomerGroupOccCustomer) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name for the customer.
func (o OccCustomerGroupOccCustomerOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *OccCustomerGroupOccCustomer) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The OCID of the customer group.
func (o OccCustomerGroupOccCustomerOutput) OccCustomerGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccCustomerGroupOccCustomer) pulumi.StringOutput { return v.OccCustomerGroupId }).(pulumi.StringOutput)
}

// (Updatable) To determine whether the customer is enabled/disabled.
func (o OccCustomerGroupOccCustomerOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *OccCustomerGroupOccCustomer) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// The OCID of the tenancy belonging to the customer.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o OccCustomerGroupOccCustomerOutput) TenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v *OccCustomerGroupOccCustomer) pulumi.StringOutput { return v.TenancyId }).(pulumi.StringOutput)
}

type OccCustomerGroupOccCustomerArrayOutput struct{ *pulumi.OutputState }

func (OccCustomerGroupOccCustomerArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OccCustomerGroupOccCustomer)(nil)).Elem()
}

func (o OccCustomerGroupOccCustomerArrayOutput) ToOccCustomerGroupOccCustomerArrayOutput() OccCustomerGroupOccCustomerArrayOutput {
	return o
}

func (o OccCustomerGroupOccCustomerArrayOutput) ToOccCustomerGroupOccCustomerArrayOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerArrayOutput {
	return o
}

func (o OccCustomerGroupOccCustomerArrayOutput) Index(i pulumi.IntInput) OccCustomerGroupOccCustomerOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *OccCustomerGroupOccCustomer {
		return vs[0].([]*OccCustomerGroupOccCustomer)[vs[1].(int)]
	}).(OccCustomerGroupOccCustomerOutput)
}

type OccCustomerGroupOccCustomerMapOutput struct{ *pulumi.OutputState }

func (OccCustomerGroupOccCustomerMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OccCustomerGroupOccCustomer)(nil)).Elem()
}

func (o OccCustomerGroupOccCustomerMapOutput) ToOccCustomerGroupOccCustomerMapOutput() OccCustomerGroupOccCustomerMapOutput {
	return o
}

func (o OccCustomerGroupOccCustomerMapOutput) ToOccCustomerGroupOccCustomerMapOutputWithContext(ctx context.Context) OccCustomerGroupOccCustomerMapOutput {
	return o
}

func (o OccCustomerGroupOccCustomerMapOutput) MapIndex(k pulumi.StringInput) OccCustomerGroupOccCustomerOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *OccCustomerGroupOccCustomer {
		return vs[0].(map[string]*OccCustomerGroupOccCustomer)[vs[1].(string)]
	}).(OccCustomerGroupOccCustomerOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*OccCustomerGroupOccCustomerInput)(nil)).Elem(), &OccCustomerGroupOccCustomer{})
	pulumi.RegisterInputType(reflect.TypeOf((*OccCustomerGroupOccCustomerArrayInput)(nil)).Elem(), OccCustomerGroupOccCustomerArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*OccCustomerGroupOccCustomerMapInput)(nil)).Elem(), OccCustomerGroupOccCustomerMap{})
	pulumi.RegisterOutputType(OccCustomerGroupOccCustomerOutput{})
	pulumi.RegisterOutputType(OccCustomerGroupOccCustomerArrayOutput{})
	pulumi.RegisterOutputType(OccCustomerGroupOccCustomerMapOutput{})
}
