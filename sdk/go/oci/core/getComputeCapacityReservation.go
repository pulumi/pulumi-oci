// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Compute Capacity Reservation resource in Oracle Cloud Infrastructure Core service.
//
// Gets information about the specified compute capacity reservation.
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
//			_, err := Core.GetComputeCapacityReservation(ctx, &core.GetComputeCapacityReservationArgs{
//				CapacityReservationId: oci_core_capacity_reservation.Test_capacity_reservation.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupComputeCapacityReservation(ctx *pulumi.Context, args *LookupComputeCapacityReservationArgs, opts ...pulumi.InvokeOption) (*LookupComputeCapacityReservationResult, error) {
	var rv LookupComputeCapacityReservationResult
	err := ctx.Invoke("oci:Core/getComputeCapacityReservation:getComputeCapacityReservation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getComputeCapacityReservation.
type LookupComputeCapacityReservationArgs struct {
	// The OCID of the compute capacity reservation.
	CapacityReservationId string `pulumi:"capacityReservationId"`
}

// A collection of values returned by getComputeCapacityReservation.
type LookupComputeCapacityReservationResult struct {
	// The availability domain of the compute capacity reservation.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain    string `pulumi:"availabilityDomain"`
	CapacityReservationId string `pulumi:"capacityReservationId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the compute capacity reservation.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity reservation.
	Id string `pulumi:"id"`
	// The capacity configurations for the capacity reservation.
	InstanceReservationConfigs []GetComputeCapacityReservationInstanceReservationConfig `pulumi:"instanceReservationConfigs"`
	// Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
	IsDefaultReservation bool `pulumi:"isDefaultReservation"`
	// The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	ReservedInstanceCount string `pulumi:"reservedInstanceCount"`
	// The current state of the compute capacity reservation.
	State string `pulumi:"state"`
	// The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
	// The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
	UsedInstanceCount string `pulumi:"usedInstanceCount"`
}

func LookupComputeCapacityReservationOutput(ctx *pulumi.Context, args LookupComputeCapacityReservationOutputArgs, opts ...pulumi.InvokeOption) LookupComputeCapacityReservationResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupComputeCapacityReservationResult, error) {
			args := v.(LookupComputeCapacityReservationArgs)
			r, err := LookupComputeCapacityReservation(ctx, &args, opts...)
			var s LookupComputeCapacityReservationResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupComputeCapacityReservationResultOutput)
}

// A collection of arguments for invoking getComputeCapacityReservation.
type LookupComputeCapacityReservationOutputArgs struct {
	// The OCID of the compute capacity reservation.
	CapacityReservationId pulumi.StringInput `pulumi:"capacityReservationId"`
}

func (LookupComputeCapacityReservationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupComputeCapacityReservationArgs)(nil)).Elem()
}

// A collection of values returned by getComputeCapacityReservation.
type LookupComputeCapacityReservationResultOutput struct{ *pulumi.OutputState }

func (LookupComputeCapacityReservationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupComputeCapacityReservationResult)(nil)).Elem()
}

func (o LookupComputeCapacityReservationResultOutput) ToLookupComputeCapacityReservationResultOutput() LookupComputeCapacityReservationResultOutput {
	return o
}

func (o LookupComputeCapacityReservationResultOutput) ToLookupComputeCapacityReservationResultOutputWithContext(ctx context.Context) LookupComputeCapacityReservationResultOutput {
	return o
}

// The availability domain of the compute capacity reservation.  Example: `Uocm:PHX-AD-1`
func (o LookupComputeCapacityReservationResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

func (o LookupComputeCapacityReservationResultOutput) CapacityReservationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.CapacityReservationId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the compute capacity reservation.
func (o LookupComputeCapacityReservationResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupComputeCapacityReservationResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupComputeCapacityReservationResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupComputeCapacityReservationResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compute capacity reservation.
func (o LookupComputeCapacityReservationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.Id }).(pulumi.StringOutput)
}

// The capacity configurations for the capacity reservation.
func (o LookupComputeCapacityReservationResultOutput) InstanceReservationConfigs() GetComputeCapacityReservationInstanceReservationConfigArrayOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) []GetComputeCapacityReservationInstanceReservationConfig {
		return v.InstanceReservationConfigs
	}).(GetComputeCapacityReservationInstanceReservationConfigArrayOutput)
}

// Whether this capacity reservation is the default. For more information, see [Capacity Reservations](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/reserve-capacity.htm#default).
func (o LookupComputeCapacityReservationResultOutput) IsDefaultReservation() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) bool { return v.IsDefaultReservation }).(pulumi.BoolOutput)
}

// The number of instances for which capacity will be held with this compute capacity reservation. This number is the sum of the values of the `reservedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
func (o LookupComputeCapacityReservationResultOutput) ReservedInstanceCount() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.ReservedInstanceCount }).(pulumi.StringOutput)
}

// The current state of the compute capacity reservation.
func (o LookupComputeCapacityReservationResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the compute capacity reservation was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupComputeCapacityReservationResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the compute capacity reservation was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupComputeCapacityReservationResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The total number of instances currently consuming space in this compute capacity reservation. This number is the sum of the values of the `usedCount` fields for all of the instance capacity configurations under this reservation. The purpose of this field is to calculate the percentage usage of the reservation.
func (o LookupComputeCapacityReservationResultOutput) UsedInstanceCount() pulumi.StringOutput {
	return o.ApplyT(func(v LookupComputeCapacityReservationResult) string { return v.UsedInstanceCount }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupComputeCapacityReservationResultOutput{})
}