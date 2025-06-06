// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package opsi

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Operations Insights Warehouse User resource in Oracle Cloud Infrastructure Opsi service.
//
// Create a Operations Insights Warehouse user resource for the tenant in Operations Insights.
// This resource will be created in root compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/opsi"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := opsi.NewOperationsInsightsWarehouseUser(ctx, "test_operations_insights_warehouse_user", &opsi.OperationsInsightsWarehouseUserArgs{
//				CompartmentId:                 pulumi.Any(compartmentId),
//				ConnectionPassword:            pulumi.Any(operationsInsightsWarehouseUserConnectionPassword),
//				IsAwrDataAccess:               pulumi.Any(operationsInsightsWarehouseUserIsAwrDataAccess),
//				Name:                          pulumi.Any(operationsInsightsWarehouseUserName),
//				OperationsInsightsWarehouseId: pulumi.Any(testOperationsInsightsWarehouse.Id),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				IsEmDataAccess:   pulumi.Any(operationsInsightsWarehouseUserIsEmDataAccess),
//				IsOpsiDataAccess: pulumi.Any(operationsInsightsWarehouseUserIsOpsiDataAccess),
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
// OperationsInsightsWarehouseUsers can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Opsi/operationsInsightsWarehouseUser:OperationsInsightsWarehouseUser test_operations_insights_warehouse_user "id"
// ```
type OperationsInsightsWarehouseUser struct {
	pulumi.CustomResourceState

	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	ConnectionPassword pulumi.StringOutput `pulumi:"connectionPassword"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) Indicate whether user has access to AWR data.
	IsAwrDataAccess pulumi.BoolOutput `pulumi:"isAwrDataAccess"`
	// (Updatable) Indicate whether user has access to EM data.
	IsEmDataAccess pulumi.BoolOutput `pulumi:"isEmDataAccess"`
	// (Updatable) Indicate whether user has access to OPSI data.
	IsOpsiDataAccess pulumi.BoolOutput `pulumi:"isOpsiDataAccess"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	Name pulumi.StringOutput `pulumi:"name"`
	// OPSI Warehouse OCID
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	OperationsInsightsWarehouseId pulumi.StringOutput `pulumi:"operationsInsightsWarehouseId"`
	// Possible lifecycle states
	State pulumi.StringOutput `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewOperationsInsightsWarehouseUser registers a new resource with the given unique name, arguments, and options.
func NewOperationsInsightsWarehouseUser(ctx *pulumi.Context,
	name string, args *OperationsInsightsWarehouseUserArgs, opts ...pulumi.ResourceOption) (*OperationsInsightsWarehouseUser, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.ConnectionPassword == nil {
		return nil, errors.New("invalid value for required argument 'ConnectionPassword'")
	}
	if args.IsAwrDataAccess == nil {
		return nil, errors.New("invalid value for required argument 'IsAwrDataAccess'")
	}
	if args.OperationsInsightsWarehouseId == nil {
		return nil, errors.New("invalid value for required argument 'OperationsInsightsWarehouseId'")
	}
	if args.ConnectionPassword != nil {
		args.ConnectionPassword = pulumi.ToSecret(args.ConnectionPassword).(pulumi.StringInput)
	}
	secrets := pulumi.AdditionalSecretOutputs([]string{
		"connectionPassword",
	})
	opts = append(opts, secrets)
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource OperationsInsightsWarehouseUser
	err := ctx.RegisterResource("oci:Opsi/operationsInsightsWarehouseUser:OperationsInsightsWarehouseUser", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetOperationsInsightsWarehouseUser gets an existing OperationsInsightsWarehouseUser resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetOperationsInsightsWarehouseUser(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *OperationsInsightsWarehouseUserState, opts ...pulumi.ResourceOption) (*OperationsInsightsWarehouseUser, error) {
	var resource OperationsInsightsWarehouseUser
	err := ctx.ReadResource("oci:Opsi/operationsInsightsWarehouseUser:OperationsInsightsWarehouseUser", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering OperationsInsightsWarehouseUser resources.
type operationsInsightsWarehouseUserState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	ConnectionPassword *string `pulumi:"connectionPassword"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Indicate whether user has access to AWR data.
	IsAwrDataAccess *bool `pulumi:"isAwrDataAccess"`
	// (Updatable) Indicate whether user has access to EM data.
	IsEmDataAccess *bool `pulumi:"isEmDataAccess"`
	// (Updatable) Indicate whether user has access to OPSI data.
	IsOpsiDataAccess *bool `pulumi:"isOpsiDataAccess"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	Name *string `pulumi:"name"`
	// OPSI Warehouse OCID
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	OperationsInsightsWarehouseId *string `pulumi:"operationsInsightsWarehouseId"`
	// Possible lifecycle states
	State *string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type OperationsInsightsWarehouseUserState struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	ConnectionPassword pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Indicate whether user has access to AWR data.
	IsAwrDataAccess pulumi.BoolPtrInput
	// (Updatable) Indicate whether user has access to EM data.
	IsEmDataAccess pulumi.BoolPtrInput
	// (Updatable) Indicate whether user has access to OPSI data.
	IsOpsiDataAccess pulumi.BoolPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	Name pulumi.StringPtrInput
	// OPSI Warehouse OCID
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	OperationsInsightsWarehouseId pulumi.StringPtrInput
	// Possible lifecycle states
	State pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
}

func (OperationsInsightsWarehouseUserState) ElementType() reflect.Type {
	return reflect.TypeOf((*operationsInsightsWarehouseUserState)(nil)).Elem()
}

type operationsInsightsWarehouseUserArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	ConnectionPassword string `pulumi:"connectionPassword"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Indicate whether user has access to AWR data.
	IsAwrDataAccess bool `pulumi:"isAwrDataAccess"`
	// (Updatable) Indicate whether user has access to EM data.
	IsEmDataAccess *bool `pulumi:"isEmDataAccess"`
	// (Updatable) Indicate whether user has access to OPSI data.
	IsOpsiDataAccess *bool `pulumi:"isOpsiDataAccess"`
	// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	Name *string `pulumi:"name"`
	// OPSI Warehouse OCID
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	OperationsInsightsWarehouseId string `pulumi:"operationsInsightsWarehouseId"`
}

// The set of arguments for constructing a OperationsInsightsWarehouseUser resource.
type OperationsInsightsWarehouseUserArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	ConnectionPassword pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Indicate whether user has access to AWR data.
	IsAwrDataAccess pulumi.BoolInput
	// (Updatable) Indicate whether user has access to EM data.
	IsEmDataAccess pulumi.BoolPtrInput
	// (Updatable) Indicate whether user has access to OPSI data.
	IsOpsiDataAccess pulumi.BoolPtrInput
	// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
	Name pulumi.StringPtrInput
	// OPSI Warehouse OCID
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	OperationsInsightsWarehouseId pulumi.StringInput
}

func (OperationsInsightsWarehouseUserArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*operationsInsightsWarehouseUserArgs)(nil)).Elem()
}

type OperationsInsightsWarehouseUserInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseUserOutput() OperationsInsightsWarehouseUserOutput
	ToOperationsInsightsWarehouseUserOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserOutput
}

func (*OperationsInsightsWarehouseUser) ElementType() reflect.Type {
	return reflect.TypeOf((**OperationsInsightsWarehouseUser)(nil)).Elem()
}

func (i *OperationsInsightsWarehouseUser) ToOperationsInsightsWarehouseUserOutput() OperationsInsightsWarehouseUserOutput {
	return i.ToOperationsInsightsWarehouseUserOutputWithContext(context.Background())
}

func (i *OperationsInsightsWarehouseUser) ToOperationsInsightsWarehouseUserOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseUserOutput)
}

// OperationsInsightsWarehouseUserArrayInput is an input type that accepts OperationsInsightsWarehouseUserArray and OperationsInsightsWarehouseUserArrayOutput values.
// You can construct a concrete instance of `OperationsInsightsWarehouseUserArrayInput` via:
//
//	OperationsInsightsWarehouseUserArray{ OperationsInsightsWarehouseUserArgs{...} }
type OperationsInsightsWarehouseUserArrayInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseUserArrayOutput() OperationsInsightsWarehouseUserArrayOutput
	ToOperationsInsightsWarehouseUserArrayOutputWithContext(context.Context) OperationsInsightsWarehouseUserArrayOutput
}

type OperationsInsightsWarehouseUserArray []OperationsInsightsWarehouseUserInput

func (OperationsInsightsWarehouseUserArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OperationsInsightsWarehouseUser)(nil)).Elem()
}

func (i OperationsInsightsWarehouseUserArray) ToOperationsInsightsWarehouseUserArrayOutput() OperationsInsightsWarehouseUserArrayOutput {
	return i.ToOperationsInsightsWarehouseUserArrayOutputWithContext(context.Background())
}

func (i OperationsInsightsWarehouseUserArray) ToOperationsInsightsWarehouseUserArrayOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseUserArrayOutput)
}

// OperationsInsightsWarehouseUserMapInput is an input type that accepts OperationsInsightsWarehouseUserMap and OperationsInsightsWarehouseUserMapOutput values.
// You can construct a concrete instance of `OperationsInsightsWarehouseUserMapInput` via:
//
//	OperationsInsightsWarehouseUserMap{ "key": OperationsInsightsWarehouseUserArgs{...} }
type OperationsInsightsWarehouseUserMapInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseUserMapOutput() OperationsInsightsWarehouseUserMapOutput
	ToOperationsInsightsWarehouseUserMapOutputWithContext(context.Context) OperationsInsightsWarehouseUserMapOutput
}

type OperationsInsightsWarehouseUserMap map[string]OperationsInsightsWarehouseUserInput

func (OperationsInsightsWarehouseUserMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OperationsInsightsWarehouseUser)(nil)).Elem()
}

func (i OperationsInsightsWarehouseUserMap) ToOperationsInsightsWarehouseUserMapOutput() OperationsInsightsWarehouseUserMapOutput {
	return i.ToOperationsInsightsWarehouseUserMapOutputWithContext(context.Background())
}

func (i OperationsInsightsWarehouseUserMap) ToOperationsInsightsWarehouseUserMapOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseUserMapOutput)
}

type OperationsInsightsWarehouseUserOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseUserOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**OperationsInsightsWarehouseUser)(nil)).Elem()
}

func (o OperationsInsightsWarehouseUserOutput) ToOperationsInsightsWarehouseUserOutput() OperationsInsightsWarehouseUserOutput {
	return o
}

func (o OperationsInsightsWarehouseUserOutput) ToOperationsInsightsWarehouseUserOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o OperationsInsightsWarehouseUserOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) User provided connection password for the AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
func (o OperationsInsightsWarehouseUserOutput) ConnectionPassword() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.ConnectionPassword }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o OperationsInsightsWarehouseUserOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o OperationsInsightsWarehouseUserOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) Indicate whether user has access to AWR data.
func (o OperationsInsightsWarehouseUserOutput) IsAwrDataAccess() pulumi.BoolOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.BoolOutput { return v.IsAwrDataAccess }).(pulumi.BoolOutput)
}

// (Updatable) Indicate whether user has access to EM data.
func (o OperationsInsightsWarehouseUserOutput) IsEmDataAccess() pulumi.BoolOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.BoolOutput { return v.IsEmDataAccess }).(pulumi.BoolOutput)
}

// (Updatable) Indicate whether user has access to OPSI data.
func (o OperationsInsightsWarehouseUserOutput) IsOpsiDataAccess() pulumi.BoolOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.BoolOutput { return v.IsOpsiDataAccess }).(pulumi.BoolOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o OperationsInsightsWarehouseUserOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Username for schema which would have access to AWR Data,  Enterprise Manager Data and Ops Insights OPSI Hub.
func (o OperationsInsightsWarehouseUserOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// OPSI Warehouse OCID
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o OperationsInsightsWarehouseUserOutput) OperationsInsightsWarehouseId() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.OperationsInsightsWarehouseId }).(pulumi.StringOutput)
}

// Possible lifecycle states
func (o OperationsInsightsWarehouseUserOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o OperationsInsightsWarehouseUserOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time at which the resource was first created. An RFC3339 formatted datetime string
func (o OperationsInsightsWarehouseUserOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time at which the resource was last updated. An RFC3339 formatted datetime string
func (o OperationsInsightsWarehouseUserOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouseUser) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type OperationsInsightsWarehouseUserArrayOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseUserArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OperationsInsightsWarehouseUser)(nil)).Elem()
}

func (o OperationsInsightsWarehouseUserArrayOutput) ToOperationsInsightsWarehouseUserArrayOutput() OperationsInsightsWarehouseUserArrayOutput {
	return o
}

func (o OperationsInsightsWarehouseUserArrayOutput) ToOperationsInsightsWarehouseUserArrayOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserArrayOutput {
	return o
}

func (o OperationsInsightsWarehouseUserArrayOutput) Index(i pulumi.IntInput) OperationsInsightsWarehouseUserOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *OperationsInsightsWarehouseUser {
		return vs[0].([]*OperationsInsightsWarehouseUser)[vs[1].(int)]
	}).(OperationsInsightsWarehouseUserOutput)
}

type OperationsInsightsWarehouseUserMapOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseUserMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OperationsInsightsWarehouseUser)(nil)).Elem()
}

func (o OperationsInsightsWarehouseUserMapOutput) ToOperationsInsightsWarehouseUserMapOutput() OperationsInsightsWarehouseUserMapOutput {
	return o
}

func (o OperationsInsightsWarehouseUserMapOutput) ToOperationsInsightsWarehouseUserMapOutputWithContext(ctx context.Context) OperationsInsightsWarehouseUserMapOutput {
	return o
}

func (o OperationsInsightsWarehouseUserMapOutput) MapIndex(k pulumi.StringInput) OperationsInsightsWarehouseUserOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *OperationsInsightsWarehouseUser {
		return vs[0].(map[string]*OperationsInsightsWarehouseUser)[vs[1].(string)]
	}).(OperationsInsightsWarehouseUserOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseUserInput)(nil)).Elem(), &OperationsInsightsWarehouseUser{})
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseUserArrayInput)(nil)).Elem(), OperationsInsightsWarehouseUserArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseUserMapInput)(nil)).Elem(), OperationsInsightsWarehouseUserMap{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseUserOutput{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseUserArrayOutput{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseUserMapOutput{})
}
