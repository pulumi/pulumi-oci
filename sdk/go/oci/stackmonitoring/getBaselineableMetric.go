// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package stackmonitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides details about a specific Baselineable Metric resource in Oracle Cloud Infrastructure Stack Monitoring service.
//
// # Get the Baseline-able metric for the given id
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/StackMonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := StackMonitoring.GetBaselineableMetric(ctx, &stackmonitoring.GetBaselineableMetricArgs{
//				BaselineableMetricId: oci_stack_monitoring_baselineable_metric.Test_baselineable_metric.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupBaselineableMetric(ctx *pulumi.Context, args *LookupBaselineableMetricArgs, opts ...pulumi.InvokeOption) (*LookupBaselineableMetricResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupBaselineableMetricResult
	err := ctx.Invoke("oci:StackMonitoring/getBaselineableMetric:getBaselineableMetric", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBaselineableMetric.
type LookupBaselineableMetricArgs struct {
	// Identifier for the metric
	BaselineableMetricId string `pulumi:"baselineableMetricId"`
}

// A collection of values returned by getBaselineableMetric.
type LookupBaselineableMetricResult struct {
	BaselineableMetricId string `pulumi:"baselineableMetricId"`
	// metric column name
	Column string `pulumi:"column"`
	// OCID of the compartment
	CompartmentId string `pulumi:"compartmentId"`
	// Created user id
	CreatedBy string `pulumi:"createdBy"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// OCID of the metric
	Id string `pulumi:"id"`
	// Is the metric created out of box, default false
	IsOutOfBox bool `pulumi:"isOutOfBox"`
	// last Updated user id
	LastUpdatedBy string `pulumi:"lastUpdatedBy"`
	// name of the metric
	Name string `pulumi:"name"`
	// namespace of the metric
	Namespace string `pulumi:"namespace"`
	// Resource group of the metric
	ResourceGroup string `pulumi:"resourceGroup"`
	// The current lifecycle state of the metric extension
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// OCID of the tenancy
	TenancyId string `pulumi:"tenancyId"`
	// creation date
	TimeCreated string `pulumi:"timeCreated"`
	// last updated time
	TimeLastUpdated string `pulumi:"timeLastUpdated"`
}

func LookupBaselineableMetricOutput(ctx *pulumi.Context, args LookupBaselineableMetricOutputArgs, opts ...pulumi.InvokeOption) LookupBaselineableMetricResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupBaselineableMetricResult, error) {
			args := v.(LookupBaselineableMetricArgs)
			r, err := LookupBaselineableMetric(ctx, &args, opts...)
			var s LookupBaselineableMetricResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupBaselineableMetricResultOutput)
}

// A collection of arguments for invoking getBaselineableMetric.
type LookupBaselineableMetricOutputArgs struct {
	// Identifier for the metric
	BaselineableMetricId pulumi.StringInput `pulumi:"baselineableMetricId"`
}

func (LookupBaselineableMetricOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupBaselineableMetricArgs)(nil)).Elem()
}

// A collection of values returned by getBaselineableMetric.
type LookupBaselineableMetricResultOutput struct{ *pulumi.OutputState }

func (LookupBaselineableMetricResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupBaselineableMetricResult)(nil)).Elem()
}

func (o LookupBaselineableMetricResultOutput) ToLookupBaselineableMetricResultOutput() LookupBaselineableMetricResultOutput {
	return o
}

func (o LookupBaselineableMetricResultOutput) ToLookupBaselineableMetricResultOutputWithContext(ctx context.Context) LookupBaselineableMetricResultOutput {
	return o
}

func (o LookupBaselineableMetricResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupBaselineableMetricResult] {
	return pulumix.Output[LookupBaselineableMetricResult]{
		OutputState: o.OutputState,
	}
}

func (o LookupBaselineableMetricResultOutput) BaselineableMetricId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.BaselineableMetricId }).(pulumi.StringOutput)
}

// metric column name
func (o LookupBaselineableMetricResultOutput) Column() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.Column }).(pulumi.StringOutput)
}

// OCID of the compartment
func (o LookupBaselineableMetricResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Created user id
func (o LookupBaselineableMetricResultOutput) CreatedBy() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.CreatedBy }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupBaselineableMetricResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupBaselineableMetricResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// OCID of the metric
func (o LookupBaselineableMetricResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.Id }).(pulumi.StringOutput)
}

// Is the metric created out of box, default false
func (o LookupBaselineableMetricResultOutput) IsOutOfBox() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) bool { return v.IsOutOfBox }).(pulumi.BoolOutput)
}

// last Updated user id
func (o LookupBaselineableMetricResultOutput) LastUpdatedBy() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.LastUpdatedBy }).(pulumi.StringOutput)
}

// name of the metric
func (o LookupBaselineableMetricResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.Name }).(pulumi.StringOutput)
}

// namespace of the metric
func (o LookupBaselineableMetricResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// Resource group of the metric
func (o LookupBaselineableMetricResultOutput) ResourceGroup() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.ResourceGroup }).(pulumi.StringOutput)
}

// The current lifecycle state of the metric extension
func (o LookupBaselineableMetricResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupBaselineableMetricResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// OCID of the tenancy
func (o LookupBaselineableMetricResultOutput) TenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.TenancyId }).(pulumi.StringOutput)
}

// creation date
func (o LookupBaselineableMetricResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// last updated time
func (o LookupBaselineableMetricResultOutput) TimeLastUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupBaselineableMetricResult) string { return v.TimeLastUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupBaselineableMetricResultOutput{})
}