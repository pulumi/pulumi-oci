// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dataflow

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Pool resource in Oracle Cloud Infrastructure Data Flow service.
//
// Retrieves a pool using a `poolId`.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataFlow"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataFlow.GetPool(ctx, &dataflow.GetPoolArgs{
//				PoolId: oci_dataflow_pool.Test_pool.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupPool(ctx *pulumi.Context, args *LookupPoolArgs, opts ...pulumi.InvokeOption) (*LookupPoolResult, error) {
	var rv LookupPoolResult
	err := ctx.Invoke("oci:DataFlow/getPool:getPool", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPool.
type LookupPoolArgs struct {
	// The unique ID for a pool.
	PoolId string `pulumi:"poolId"`
}

// A collection of values returned by getPool.
type LookupPoolResult struct {
	// The OCID of a compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// List of PoolConfig items.
	Configurations []GetPoolConfiguration `pulumi:"configurations"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly description. Avoid entering confidential information.
	Description string `pulumi:"description"`
	// A user-friendly name. It does not have to be unique. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of a pool. Unique Id to indentify a dataflow pool resource.
	Id string `pulumi:"id"`
	// Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
	IdleTimeoutInMinutes int `pulumi:"idleTimeoutInMinutes"`
	// The detailed messages about the lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The OCID of the user who created the resource.
	OwnerPrincipalId string `pulumi:"ownerPrincipalId"`
	// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
	OwnerUserName string `pulumi:"ownerUserName"`
	PoolId        string `pulumi:"poolId"`
	// A collection of metrics related to a particular pool.
	PoolMetrics []GetPoolPoolMetric `pulumi:"poolMetrics"`
	// A list of schedules for pool to auto start and stop.
	Schedules []GetPoolSchedule `pulumi:"schedules"`
	// The current state of this pool.
	State string `pulumi:"state"`
	// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupPoolOutput(ctx *pulumi.Context, args LookupPoolOutputArgs, opts ...pulumi.InvokeOption) LookupPoolResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupPoolResult, error) {
			args := v.(LookupPoolArgs)
			r, err := LookupPool(ctx, &args, opts...)
			var s LookupPoolResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupPoolResultOutput)
}

// A collection of arguments for invoking getPool.
type LookupPoolOutputArgs struct {
	// The unique ID for a pool.
	PoolId pulumi.StringInput `pulumi:"poolId"`
}

func (LookupPoolOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPoolArgs)(nil)).Elem()
}

// A collection of values returned by getPool.
type LookupPoolResultOutput struct{ *pulumi.OutputState }

func (LookupPoolResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPoolResult)(nil)).Elem()
}

func (o LookupPoolResultOutput) ToLookupPoolResultOutput() LookupPoolResultOutput {
	return o
}

func (o LookupPoolResultOutput) ToLookupPoolResultOutputWithContext(ctx context.Context) LookupPoolResultOutput {
	return o
}

// The OCID of a compartment.
func (o LookupPoolResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// List of PoolConfig items.
func (o LookupPoolResultOutput) Configurations() GetPoolConfigurationArrayOutput {
	return o.ApplyT(func(v LookupPoolResult) []GetPoolConfiguration { return v.Configurations }).(GetPoolConfigurationArrayOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupPoolResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupPoolResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A user-friendly description. Avoid entering confidential information.
func (o LookupPoolResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.Description }).(pulumi.StringOutput)
}

// A user-friendly name. It does not have to be unique. Avoid entering confidential information.
func (o LookupPoolResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupPoolResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupPoolResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of a pool. Unique Id to indentify a dataflow pool resource.
func (o LookupPoolResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.Id }).(pulumi.StringOutput)
}

// Optional timeout value in minutes used to auto stop Pools. A Pool will be auto stopped after inactivity for this amount of time period. If value not set, pool will not be auto stopped auto.
func (o LookupPoolResultOutput) IdleTimeoutInMinutes() pulumi.IntOutput {
	return o.ApplyT(func(v LookupPoolResult) int { return v.IdleTimeoutInMinutes }).(pulumi.IntOutput)
}

// The detailed messages about the lifecycle state.
func (o LookupPoolResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the user who created the resource.
func (o LookupPoolResultOutput) OwnerPrincipalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.OwnerPrincipalId }).(pulumi.StringOutput)
}

// The username of the user who created the resource.  If the username of the owner does not exist, `null` will be returned and the caller should refer to the ownerPrincipalId value instead.
func (o LookupPoolResultOutput) OwnerUserName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.OwnerUserName }).(pulumi.StringOutput)
}

func (o LookupPoolResultOutput) PoolId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.PoolId }).(pulumi.StringOutput)
}

// A collection of metrics related to a particular pool.
func (o LookupPoolResultOutput) PoolMetrics() GetPoolPoolMetricArrayOutput {
	return o.ApplyT(func(v LookupPoolResult) []GetPoolPoolMetric { return v.PoolMetrics }).(GetPoolPoolMetricArrayOutput)
}

// A list of schedules for pool to auto start and stop.
func (o LookupPoolResultOutput) Schedules() GetPoolScheduleArrayOutput {
	return o.ApplyT(func(v LookupPoolResult) []GetPoolSchedule { return v.Schedules }).(GetPoolScheduleArrayOutput)
}

// The current state of this pool.
func (o LookupPoolResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
func (o LookupPoolResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2018-04-03T21:10:29.600Z`
func (o LookupPoolResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPoolResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupPoolResultOutput{})
}