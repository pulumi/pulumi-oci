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

// This resource provides the Operations Insights Warehouse resource in Oracle Cloud Infrastructure Opsi service.
//
// Create a Ops Insights Warehouse resource for the tenant in Ops Insights. New ADW will be provisioned for this tenant.
// There is only expected to be 1 warehouse per tenant. The warehouse is expected to be in the root compartment. If the 'opsi-warehouse-type'
// header is passed to the API, a warehouse resource without ADW or Schema provisioning is created.
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
//			_, err := opsi.NewOperationsInsightsWarehouse(ctx, "test_operations_insights_warehouse", &opsi.OperationsInsightsWarehouseArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				CpuAllocated:  pulumi.Any(operationsInsightsWarehouseCpuAllocated),
//				DisplayName:   pulumi.Any(operationsInsightsWarehouseDisplayName),
//				ComputeModel:  pulumi.Any(operationsInsightsWarehouseComputeModel),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				StorageAllocatedInGbs: pulumi.Any(operationsInsightsWarehouseStorageAllocatedInGbs),
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
// OperationsInsightsWarehouses can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Opsi/operationsInsightsWarehouse:OperationsInsightsWarehouse test_operations_insights_warehouse "id"
// ```
type OperationsInsightsWarehouse struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The compute model for the OPSI warehouse ADW (OCPU or ECPU)
	ComputeModel pulumi.StringOutput `pulumi:"computeModel"`
	// (Updatable) Number of CPUs allocated to OPSI Warehouse ADW.
	CpuAllocated pulumi.Float64Output `pulumi:"cpuAllocated"`
	// Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
	CpuUsed pulumi.Float64Output `pulumi:"cpuUsed"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) User-friedly name of Ops Insights Warehouse that does not have to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// OCID of the dynamic group created for the warehouse
	DynamicGroupId pulumi.StringOutput `pulumi:"dynamicGroupId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Tenancy Identifier of Ops Insights service
	OperationsInsightsTenancyId pulumi.StringOutput `pulumi:"operationsInsightsTenancyId"`
	// Possible lifecycle states
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) Storage allocated to OPSI Warehouse ADW.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageAllocatedInGbs pulumi.Float64Output `pulumi:"storageAllocatedInGbs"`
	// Storage by OPSI Warehouse ADW in GB.
	StorageUsedInGbs pulumi.Float64Output `pulumi:"storageUsedInGbs"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time at which the ADW wallet was last rotated for the Ops Insights Warehouse. An RFC3339 formatted datetime string
	TimeLastWalletRotated pulumi.StringOutput `pulumi:"timeLastWalletRotated"`
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewOperationsInsightsWarehouse registers a new resource with the given unique name, arguments, and options.
func NewOperationsInsightsWarehouse(ctx *pulumi.Context,
	name string, args *OperationsInsightsWarehouseArgs, opts ...pulumi.ResourceOption) (*OperationsInsightsWarehouse, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.CpuAllocated == nil {
		return nil, errors.New("invalid value for required argument 'CpuAllocated'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource OperationsInsightsWarehouse
	err := ctx.RegisterResource("oci:Opsi/operationsInsightsWarehouse:OperationsInsightsWarehouse", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetOperationsInsightsWarehouse gets an existing OperationsInsightsWarehouse resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetOperationsInsightsWarehouse(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *OperationsInsightsWarehouseState, opts ...pulumi.ResourceOption) (*OperationsInsightsWarehouse, error) {
	var resource OperationsInsightsWarehouse
	err := ctx.ReadResource("oci:Opsi/operationsInsightsWarehouse:OperationsInsightsWarehouse", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering OperationsInsightsWarehouse resources.
type operationsInsightsWarehouseState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The compute model for the OPSI warehouse ADW (OCPU or ECPU)
	ComputeModel *string `pulumi:"computeModel"`
	// (Updatable) Number of CPUs allocated to OPSI Warehouse ADW.
	CpuAllocated *float64 `pulumi:"cpuAllocated"`
	// Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
	CpuUsed *float64 `pulumi:"cpuUsed"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) User-friedly name of Ops Insights Warehouse that does not have to be unique.
	DisplayName *string `pulumi:"displayName"`
	// OCID of the dynamic group created for the warehouse
	DynamicGroupId *string `pulumi:"dynamicGroupId"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Tenancy Identifier of Ops Insights service
	OperationsInsightsTenancyId *string `pulumi:"operationsInsightsTenancyId"`
	// Possible lifecycle states
	State *string `pulumi:"state"`
	// (Updatable) Storage allocated to OPSI Warehouse ADW.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageAllocatedInGbs *float64 `pulumi:"storageAllocatedInGbs"`
	// Storage by OPSI Warehouse ADW in GB.
	StorageUsedInGbs *float64 `pulumi:"storageUsedInGbs"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time at which the ADW wallet was last rotated for the Ops Insights Warehouse. An RFC3339 formatted datetime string
	TimeLastWalletRotated *string `pulumi:"timeLastWalletRotated"`
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type OperationsInsightsWarehouseState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The compute model for the OPSI warehouse ADW (OCPU or ECPU)
	ComputeModel pulumi.StringPtrInput
	// (Updatable) Number of CPUs allocated to OPSI Warehouse ADW.
	CpuAllocated pulumi.Float64PtrInput
	// Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
	CpuUsed pulumi.Float64PtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) User-friedly name of Ops Insights Warehouse that does not have to be unique.
	DisplayName pulumi.StringPtrInput
	// OCID of the dynamic group created for the warehouse
	DynamicGroupId pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// Tenancy Identifier of Ops Insights service
	OperationsInsightsTenancyId pulumi.StringPtrInput
	// Possible lifecycle states
	State pulumi.StringPtrInput
	// (Updatable) Storage allocated to OPSI Warehouse ADW.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageAllocatedInGbs pulumi.Float64PtrInput
	// Storage by OPSI Warehouse ADW in GB.
	StorageUsedInGbs pulumi.Float64PtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time at which the resource was first created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time at which the ADW wallet was last rotated for the Ops Insights Warehouse. An RFC3339 formatted datetime string
	TimeLastWalletRotated pulumi.StringPtrInput
	// The time at which the resource was last updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
}

func (OperationsInsightsWarehouseState) ElementType() reflect.Type {
	return reflect.TypeOf((*operationsInsightsWarehouseState)(nil)).Elem()
}

type operationsInsightsWarehouseArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The compute model for the OPSI warehouse ADW (OCPU or ECPU)
	ComputeModel *string `pulumi:"computeModel"`
	// (Updatable) Number of CPUs allocated to OPSI Warehouse ADW.
	CpuAllocated float64 `pulumi:"cpuAllocated"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) User-friedly name of Ops Insights Warehouse that does not have to be unique.
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Storage allocated to OPSI Warehouse ADW.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageAllocatedInGbs *float64 `pulumi:"storageAllocatedInGbs"`
}

// The set of arguments for constructing a OperationsInsightsWarehouse resource.
type OperationsInsightsWarehouseArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) The compute model for the OPSI warehouse ADW (OCPU or ECPU)
	ComputeModel pulumi.StringPtrInput
	// (Updatable) Number of CPUs allocated to OPSI Warehouse ADW.
	CpuAllocated pulumi.Float64Input
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) User-friedly name of Ops Insights Warehouse that does not have to be unique.
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) Storage allocated to OPSI Warehouse ADW.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	StorageAllocatedInGbs pulumi.Float64PtrInput
}

func (OperationsInsightsWarehouseArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*operationsInsightsWarehouseArgs)(nil)).Elem()
}

type OperationsInsightsWarehouseInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseOutput() OperationsInsightsWarehouseOutput
	ToOperationsInsightsWarehouseOutputWithContext(ctx context.Context) OperationsInsightsWarehouseOutput
}

func (*OperationsInsightsWarehouse) ElementType() reflect.Type {
	return reflect.TypeOf((**OperationsInsightsWarehouse)(nil)).Elem()
}

func (i *OperationsInsightsWarehouse) ToOperationsInsightsWarehouseOutput() OperationsInsightsWarehouseOutput {
	return i.ToOperationsInsightsWarehouseOutputWithContext(context.Background())
}

func (i *OperationsInsightsWarehouse) ToOperationsInsightsWarehouseOutputWithContext(ctx context.Context) OperationsInsightsWarehouseOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseOutput)
}

// OperationsInsightsWarehouseArrayInput is an input type that accepts OperationsInsightsWarehouseArray and OperationsInsightsWarehouseArrayOutput values.
// You can construct a concrete instance of `OperationsInsightsWarehouseArrayInput` via:
//
//	OperationsInsightsWarehouseArray{ OperationsInsightsWarehouseArgs{...} }
type OperationsInsightsWarehouseArrayInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseArrayOutput() OperationsInsightsWarehouseArrayOutput
	ToOperationsInsightsWarehouseArrayOutputWithContext(context.Context) OperationsInsightsWarehouseArrayOutput
}

type OperationsInsightsWarehouseArray []OperationsInsightsWarehouseInput

func (OperationsInsightsWarehouseArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OperationsInsightsWarehouse)(nil)).Elem()
}

func (i OperationsInsightsWarehouseArray) ToOperationsInsightsWarehouseArrayOutput() OperationsInsightsWarehouseArrayOutput {
	return i.ToOperationsInsightsWarehouseArrayOutputWithContext(context.Background())
}

func (i OperationsInsightsWarehouseArray) ToOperationsInsightsWarehouseArrayOutputWithContext(ctx context.Context) OperationsInsightsWarehouseArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseArrayOutput)
}

// OperationsInsightsWarehouseMapInput is an input type that accepts OperationsInsightsWarehouseMap and OperationsInsightsWarehouseMapOutput values.
// You can construct a concrete instance of `OperationsInsightsWarehouseMapInput` via:
//
//	OperationsInsightsWarehouseMap{ "key": OperationsInsightsWarehouseArgs{...} }
type OperationsInsightsWarehouseMapInput interface {
	pulumi.Input

	ToOperationsInsightsWarehouseMapOutput() OperationsInsightsWarehouseMapOutput
	ToOperationsInsightsWarehouseMapOutputWithContext(context.Context) OperationsInsightsWarehouseMapOutput
}

type OperationsInsightsWarehouseMap map[string]OperationsInsightsWarehouseInput

func (OperationsInsightsWarehouseMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OperationsInsightsWarehouse)(nil)).Elem()
}

func (i OperationsInsightsWarehouseMap) ToOperationsInsightsWarehouseMapOutput() OperationsInsightsWarehouseMapOutput {
	return i.ToOperationsInsightsWarehouseMapOutputWithContext(context.Background())
}

func (i OperationsInsightsWarehouseMap) ToOperationsInsightsWarehouseMapOutputWithContext(ctx context.Context) OperationsInsightsWarehouseMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(OperationsInsightsWarehouseMapOutput)
}

type OperationsInsightsWarehouseOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**OperationsInsightsWarehouse)(nil)).Elem()
}

func (o OperationsInsightsWarehouseOutput) ToOperationsInsightsWarehouseOutput() OperationsInsightsWarehouseOutput {
	return o
}

func (o OperationsInsightsWarehouseOutput) ToOperationsInsightsWarehouseOutputWithContext(ctx context.Context) OperationsInsightsWarehouseOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o OperationsInsightsWarehouseOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The compute model for the OPSI warehouse ADW (OCPU or ECPU)
func (o OperationsInsightsWarehouseOutput) ComputeModel() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.ComputeModel }).(pulumi.StringOutput)
}

// (Updatable) Number of CPUs allocated to OPSI Warehouse ADW.
func (o OperationsInsightsWarehouseOutput) CpuAllocated() pulumi.Float64Output {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.Float64Output { return v.CpuAllocated }).(pulumi.Float64Output)
}

// Number of OCPUs used by OPSI Warehouse ADW. Can be fractional.
func (o OperationsInsightsWarehouseOutput) CpuUsed() pulumi.Float64Output {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.Float64Output { return v.CpuUsed }).(pulumi.Float64Output)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o OperationsInsightsWarehouseOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) User-friedly name of Ops Insights Warehouse that does not have to be unique.
func (o OperationsInsightsWarehouseOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// OCID of the dynamic group created for the warehouse
func (o OperationsInsightsWarehouseOutput) DynamicGroupId() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.DynamicGroupId }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o OperationsInsightsWarehouseOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o OperationsInsightsWarehouseOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Tenancy Identifier of Ops Insights service
func (o OperationsInsightsWarehouseOutput) OperationsInsightsTenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.OperationsInsightsTenancyId }).(pulumi.StringOutput)
}

// Possible lifecycle states
func (o OperationsInsightsWarehouseOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) Storage allocated to OPSI Warehouse ADW.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o OperationsInsightsWarehouseOutput) StorageAllocatedInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.Float64Output { return v.StorageAllocatedInGbs }).(pulumi.Float64Output)
}

// Storage by OPSI Warehouse ADW in GB.
func (o OperationsInsightsWarehouseOutput) StorageUsedInGbs() pulumi.Float64Output {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.Float64Output { return v.StorageUsedInGbs }).(pulumi.Float64Output)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o OperationsInsightsWarehouseOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time at which the resource was first created. An RFC3339 formatted datetime string
func (o OperationsInsightsWarehouseOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time at which the ADW wallet was last rotated for the Ops Insights Warehouse. An RFC3339 formatted datetime string
func (o OperationsInsightsWarehouseOutput) TimeLastWalletRotated() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.TimeLastWalletRotated }).(pulumi.StringOutput)
}

// The time at which the resource was last updated. An RFC3339 formatted datetime string
func (o OperationsInsightsWarehouseOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *OperationsInsightsWarehouse) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type OperationsInsightsWarehouseArrayOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*OperationsInsightsWarehouse)(nil)).Elem()
}

func (o OperationsInsightsWarehouseArrayOutput) ToOperationsInsightsWarehouseArrayOutput() OperationsInsightsWarehouseArrayOutput {
	return o
}

func (o OperationsInsightsWarehouseArrayOutput) ToOperationsInsightsWarehouseArrayOutputWithContext(ctx context.Context) OperationsInsightsWarehouseArrayOutput {
	return o
}

func (o OperationsInsightsWarehouseArrayOutput) Index(i pulumi.IntInput) OperationsInsightsWarehouseOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *OperationsInsightsWarehouse {
		return vs[0].([]*OperationsInsightsWarehouse)[vs[1].(int)]
	}).(OperationsInsightsWarehouseOutput)
}

type OperationsInsightsWarehouseMapOutput struct{ *pulumi.OutputState }

func (OperationsInsightsWarehouseMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*OperationsInsightsWarehouse)(nil)).Elem()
}

func (o OperationsInsightsWarehouseMapOutput) ToOperationsInsightsWarehouseMapOutput() OperationsInsightsWarehouseMapOutput {
	return o
}

func (o OperationsInsightsWarehouseMapOutput) ToOperationsInsightsWarehouseMapOutputWithContext(ctx context.Context) OperationsInsightsWarehouseMapOutput {
	return o
}

func (o OperationsInsightsWarehouseMapOutput) MapIndex(k pulumi.StringInput) OperationsInsightsWarehouseOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *OperationsInsightsWarehouse {
		return vs[0].(map[string]*OperationsInsightsWarehouse)[vs[1].(string)]
	}).(OperationsInsightsWarehouseOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseInput)(nil)).Elem(), &OperationsInsightsWarehouse{})
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseArrayInput)(nil)).Elem(), OperationsInsightsWarehouseArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*OperationsInsightsWarehouseMapInput)(nil)).Elem(), OperationsInsightsWarehouseMap{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseOutput{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseArrayOutput{})
	pulumi.RegisterOutputType(OperationsInsightsWarehouseMapOutput{})
}
