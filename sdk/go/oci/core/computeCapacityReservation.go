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

// This resource provides the Compute Capacity Reservation resource in Oracle Cloud Infrastructure Core service.
//
// Creates a new compute capacity reservation in the specified compartment and availability domain.
// Compute capacity reservations let you reserve instances in a compartment.
// When you launch an instance using this reservation, you are assured that you have enough space for your instance,
// and you won't get out of capacity errors.
// For more information, see [Reserved Capacity](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm).
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
//			_, err := core.NewComputeCapacityReservation(ctx, "test_compute_capacity_reservation", &core.ComputeCapacityReservationArgs{
//				AvailabilityDomain: pulumi.Any(computeCapacityReservationAvailabilityDomain),
//				CompartmentId:      pulumi.Any(compartmentId),
//				DefinedTags: pulumi.StringMap{
//					"Operations.CostCenter": pulumi.String("42"),
//				},
//				DisplayName: pulumi.Any(computeCapacityReservationDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//				InstanceReservationConfigs: core.ComputeCapacityReservationInstanceReservationConfigArray{
//					&core.ComputeCapacityReservationInstanceReservationConfigArgs{
//						InstanceShape: pulumi.Any(computeCapacityReservationInstanceReservationConfigsInstanceShape),
//						ReservedCount: pulumi.Any(computeCapacityReservationInstanceReservationConfigsReservedCount),
//						ClusterConfig: &core.ComputeCapacityReservationInstanceReservationConfigClusterConfigArgs{
//							HpcIslandId:     pulumi.Any(testHpcIsland.Id),
//							NetworkBlockIds: pulumi.Any(computeCapacityReservationInstanceReservationConfigsClusterConfigNetworkBlockIds),
//						},
//						ClusterPlacementGroupId: pulumi.Any(testGroup.Id),
//						FaultDomain:             pulumi.Any(computeCapacityReservationInstanceReservationConfigsFaultDomain),
//						InstanceShapeConfig: &core.ComputeCapacityReservationInstanceReservationConfigInstanceShapeConfigArgs{
//							MemoryInGbs: pulumi.Any(computeCapacityReservationInstanceReservationConfigsInstanceShapeConfigMemoryInGbs),
//							Ocpus:       pulumi.Any(computeCapacityReservationInstanceReservationConfigsInstanceShapeConfigOcpus),
//						},
//					},
//				},
//				IsDefaultReservation: pulumi.Any(computeCapacityReservationIsDefaultReservation),
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
// ComputeCapacityReservations can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Core/computeCapacityReservation:ComputeCapacityReservation test_compute_capacity_reservation "id"
// ```
type ComputeCapacityReservation struct {
	pulumi.CustomResourceState

	// The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instanceReservationConfigs field in Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
	//
	// To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
	InstanceReservationConfigs ComputeCapacityReservationInstanceReservationConfigArrayOutput `pulumi:"instanceReservationConfigs"`
	// (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	IsDefaultReservation pulumi.BoolOutput `pulumi:"isDefaultReservation"`
	// The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	ReservedInstanceCount pulumi.StringOutput `pulumi:"reservedInstanceCount"`
	// The current state of the compute capacity reservation.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	UsedInstanceCount pulumi.StringOutput `pulumi:"usedInstanceCount"`
}

// NewComputeCapacityReservation registers a new resource with the given unique name, arguments, and options.
func NewComputeCapacityReservation(ctx *pulumi.Context,
	name string, args *ComputeCapacityReservationArgs, opts ...pulumi.ResourceOption) (*ComputeCapacityReservation, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AvailabilityDomain == nil {
		return nil, errors.New("invalid value for required argument 'AvailabilityDomain'")
	}
	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.InstanceReservationConfigs == nil {
		return nil, errors.New("invalid value for required argument 'InstanceReservationConfigs'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ComputeCapacityReservation
	err := ctx.RegisterResource("oci:Core/computeCapacityReservation:ComputeCapacityReservation", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetComputeCapacityReservation gets an existing ComputeCapacityReservation resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetComputeCapacityReservation(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ComputeCapacityReservationState, opts ...pulumi.ResourceOption) (*ComputeCapacityReservation, error) {
	var resource ComputeCapacityReservation
	err := ctx.ReadResource("oci:Core/computeCapacityReservation:ComputeCapacityReservation", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ComputeCapacityReservation resources.
type computeCapacityReservationState struct {
	// The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instanceReservationConfigs field in Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
	//
	// To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
	InstanceReservationConfigs []ComputeCapacityReservationInstanceReservationConfig `pulumi:"instanceReservationConfigs"`
	// (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	IsDefaultReservation *bool `pulumi:"isDefaultReservation"`
	// The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	ReservedInstanceCount *string `pulumi:"reservedInstanceCount"`
	// The current state of the compute capacity reservation.
	State *string `pulumi:"state"`
	// The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	UsedInstanceCount *string `pulumi:"usedInstanceCount"`
}

type ComputeCapacityReservationState struct {
	// The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instanceReservationConfigs field in Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
	//
	// To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
	InstanceReservationConfigs ComputeCapacityReservationInstanceReservationConfigArrayInput
	// (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	IsDefaultReservation pulumi.BoolPtrInput
	// The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	ReservedInstanceCount pulumi.StringPtrInput
	// The current state of the compute capacity reservation.
	State pulumi.StringPtrInput
	// The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringPtrInput
	// The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	UsedInstanceCount pulumi.StringPtrInput
}

func (ComputeCapacityReservationState) ElementType() reflect.Type {
	return reflect.TypeOf((*computeCapacityReservationState)(nil)).Elem()
}

type computeCapacityReservationArgs struct {
	// The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instanceReservationConfigs field in Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
	//
	// To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
	InstanceReservationConfigs []ComputeCapacityReservationInstanceReservationConfig `pulumi:"instanceReservationConfigs"`
	// (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	IsDefaultReservation *bool `pulumi:"isDefaultReservation"`
}

// The set of arguments for constructing a ComputeCapacityReservation resource.
type ComputeCapacityReservationArgs struct {
	// The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instanceReservationConfigs field in Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
	//
	// To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
	InstanceReservationConfigs ComputeCapacityReservationInstanceReservationConfigArrayInput
	// (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	IsDefaultReservation pulumi.BoolPtrInput
}

func (ComputeCapacityReservationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*computeCapacityReservationArgs)(nil)).Elem()
}

type ComputeCapacityReservationInput interface {
	pulumi.Input

	ToComputeCapacityReservationOutput() ComputeCapacityReservationOutput
	ToComputeCapacityReservationOutputWithContext(ctx context.Context) ComputeCapacityReservationOutput
}

func (*ComputeCapacityReservation) ElementType() reflect.Type {
	return reflect.TypeOf((**ComputeCapacityReservation)(nil)).Elem()
}

func (i *ComputeCapacityReservation) ToComputeCapacityReservationOutput() ComputeCapacityReservationOutput {
	return i.ToComputeCapacityReservationOutputWithContext(context.Background())
}

func (i *ComputeCapacityReservation) ToComputeCapacityReservationOutputWithContext(ctx context.Context) ComputeCapacityReservationOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ComputeCapacityReservationOutput)
}

// ComputeCapacityReservationArrayInput is an input type that accepts ComputeCapacityReservationArray and ComputeCapacityReservationArrayOutput values.
// You can construct a concrete instance of `ComputeCapacityReservationArrayInput` via:
//
//	ComputeCapacityReservationArray{ ComputeCapacityReservationArgs{...} }
type ComputeCapacityReservationArrayInput interface {
	pulumi.Input

	ToComputeCapacityReservationArrayOutput() ComputeCapacityReservationArrayOutput
	ToComputeCapacityReservationArrayOutputWithContext(context.Context) ComputeCapacityReservationArrayOutput
}

type ComputeCapacityReservationArray []ComputeCapacityReservationInput

func (ComputeCapacityReservationArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ComputeCapacityReservation)(nil)).Elem()
}

func (i ComputeCapacityReservationArray) ToComputeCapacityReservationArrayOutput() ComputeCapacityReservationArrayOutput {
	return i.ToComputeCapacityReservationArrayOutputWithContext(context.Background())
}

func (i ComputeCapacityReservationArray) ToComputeCapacityReservationArrayOutputWithContext(ctx context.Context) ComputeCapacityReservationArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ComputeCapacityReservationArrayOutput)
}

// ComputeCapacityReservationMapInput is an input type that accepts ComputeCapacityReservationMap and ComputeCapacityReservationMapOutput values.
// You can construct a concrete instance of `ComputeCapacityReservationMapInput` via:
//
//	ComputeCapacityReservationMap{ "key": ComputeCapacityReservationArgs{...} }
type ComputeCapacityReservationMapInput interface {
	pulumi.Input

	ToComputeCapacityReservationMapOutput() ComputeCapacityReservationMapOutput
	ToComputeCapacityReservationMapOutputWithContext(context.Context) ComputeCapacityReservationMapOutput
}

type ComputeCapacityReservationMap map[string]ComputeCapacityReservationInput

func (ComputeCapacityReservationMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ComputeCapacityReservation)(nil)).Elem()
}

func (i ComputeCapacityReservationMap) ToComputeCapacityReservationMapOutput() ComputeCapacityReservationMapOutput {
	return i.ToComputeCapacityReservationMapOutputWithContext(context.Background())
}

func (i ComputeCapacityReservationMap) ToComputeCapacityReservationMapOutputWithContext(ctx context.Context) ComputeCapacityReservationMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ComputeCapacityReservationMapOutput)
}

type ComputeCapacityReservationOutput struct{ *pulumi.OutputState }

func (ComputeCapacityReservationOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ComputeCapacityReservation)(nil)).Elem()
}

func (o ComputeCapacityReservationOutput) ToComputeCapacityReservationOutput() ComputeCapacityReservationOutput {
	return o
}

func (o ComputeCapacityReservationOutput) ToComputeCapacityReservationOutputWithContext(ctx context.Context) ComputeCapacityReservationOutput {
	return o
}

// The availability domain of this compute capacity reservation.  Example: `Uocm:PHX-AD-1`
func (o ComputeCapacityReservationOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the capacity reservation.
func (o ComputeCapacityReservationOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o ComputeCapacityReservationOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o ComputeCapacityReservationOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o ComputeCapacityReservationOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) The capacity configurations for the capacity reservation. (Note: From 6.17.0 instanceReservationConfigs field in Core.ComputeCapacityReservation is changed from TypeList to TypeSet - to avoid unnecessary updates. Also, configs cant by accessed by index)
//
// To use the reservation for the desired shape, specify the shape, count, and optionally the fault domain where you want this configuration.
func (o ComputeCapacityReservationOutput) InstanceReservationConfigs() ComputeCapacityReservationInstanceReservationConfigArrayOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) ComputeCapacityReservationInstanceReservationConfigArrayOutput {
		return v.InstanceReservationConfigs
	}).(ComputeCapacityReservationInstanceReservationConfigArrayOutput)
}

// (Updatable) Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ComputeCapacityReservationOutput) IsDefaultReservation() pulumi.BoolOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.BoolOutput { return v.IsDefaultReservation }).(pulumi.BoolOutput)
}

// The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
func (o ComputeCapacityReservationOutput) ReservedInstanceCount() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.ReservedInstanceCount }).(pulumi.StringOutput)
}

// The current state of the compute capacity reservation.
func (o ComputeCapacityReservationOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ComputeCapacityReservationOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o ComputeCapacityReservationOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
func (o ComputeCapacityReservationOutput) UsedInstanceCount() pulumi.StringOutput {
	return o.ApplyT(func(v *ComputeCapacityReservation) pulumi.StringOutput { return v.UsedInstanceCount }).(pulumi.StringOutput)
}

type ComputeCapacityReservationArrayOutput struct{ *pulumi.OutputState }

func (ComputeCapacityReservationArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ComputeCapacityReservation)(nil)).Elem()
}

func (o ComputeCapacityReservationArrayOutput) ToComputeCapacityReservationArrayOutput() ComputeCapacityReservationArrayOutput {
	return o
}

func (o ComputeCapacityReservationArrayOutput) ToComputeCapacityReservationArrayOutputWithContext(ctx context.Context) ComputeCapacityReservationArrayOutput {
	return o
}

func (o ComputeCapacityReservationArrayOutput) Index(i pulumi.IntInput) ComputeCapacityReservationOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ComputeCapacityReservation {
		return vs[0].([]*ComputeCapacityReservation)[vs[1].(int)]
	}).(ComputeCapacityReservationOutput)
}

type ComputeCapacityReservationMapOutput struct{ *pulumi.OutputState }

func (ComputeCapacityReservationMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ComputeCapacityReservation)(nil)).Elem()
}

func (o ComputeCapacityReservationMapOutput) ToComputeCapacityReservationMapOutput() ComputeCapacityReservationMapOutput {
	return o
}

func (o ComputeCapacityReservationMapOutput) ToComputeCapacityReservationMapOutputWithContext(ctx context.Context) ComputeCapacityReservationMapOutput {
	return o
}

func (o ComputeCapacityReservationMapOutput) MapIndex(k pulumi.StringInput) ComputeCapacityReservationOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ComputeCapacityReservation {
		return vs[0].(map[string]*ComputeCapacityReservation)[vs[1].(string)]
	}).(ComputeCapacityReservationOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ComputeCapacityReservationInput)(nil)).Elem(), &ComputeCapacityReservation{})
	pulumi.RegisterInputType(reflect.TypeOf((*ComputeCapacityReservationArrayInput)(nil)).Elem(), ComputeCapacityReservationArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ComputeCapacityReservationMapInput)(nil)).Elem(), ComputeCapacityReservationMap{})
	pulumi.RegisterOutputType(ComputeCapacityReservationOutput{})
	pulumi.RegisterOutputType(ComputeCapacityReservationArrayOutput{})
	pulumi.RegisterOutputType(ComputeCapacityReservationMapOutput{})
}
