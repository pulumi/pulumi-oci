// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerengine

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Cluster Workload Mapping resource in Oracle Cloud Infrastructure Container Engine service.
//
// Get the specified workloadMapping for a cluster.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ContainerEngine"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ContainerEngine.GetClusterWorkloadMapping(ctx, &containerengine.GetClusterWorkloadMappingArgs{
//				ClusterId:         oci_containerengine_cluster.Test_cluster.Id,
//				WorkloadMappingId: oci_containerengine_workload_mapping.Test_workload_mapping.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupClusterWorkloadMapping(ctx *pulumi.Context, args *LookupClusterWorkloadMappingArgs, opts ...pulumi.InvokeOption) (*LookupClusterWorkloadMappingResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupClusterWorkloadMappingResult
	err := ctx.Invoke("oci:ContainerEngine/getClusterWorkloadMapping:getClusterWorkloadMapping", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getClusterWorkloadMapping.
type LookupClusterWorkloadMappingArgs struct {
	// The OCID of the cluster.
	ClusterId string `pulumi:"clusterId"`
	// The OCID of the workloadMapping.
	WorkloadMappingId string `pulumi:"workloadMappingId"`
}

// A collection of values returned by getClusterWorkloadMapping.
type LookupClusterWorkloadMappingResult struct {
	// The OCID of the cluster.
	ClusterId string `pulumi:"clusterId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The ocid of the workloadMapping.
	Id string `pulumi:"id"`
	// The OCID of the mapped customer compartment.
	MappedCompartmentId string `pulumi:"mappedCompartmentId"`
	// The OCID of the mapped customer tenancy.
	MappedTenancyId string `pulumi:"mappedTenancyId"`
	// The namespace of the workloadMapping.
	Namespace string `pulumi:"namespace"`
	// The state of the workloadMapping.
	State string `pulumi:"state"`
	// The time the cluster was created.
	TimeCreated       string `pulumi:"timeCreated"`
	WorkloadMappingId string `pulumi:"workloadMappingId"`
}

func LookupClusterWorkloadMappingOutput(ctx *pulumi.Context, args LookupClusterWorkloadMappingOutputArgs, opts ...pulumi.InvokeOption) LookupClusterWorkloadMappingResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupClusterWorkloadMappingResult, error) {
			args := v.(LookupClusterWorkloadMappingArgs)
			r, err := LookupClusterWorkloadMapping(ctx, &args, opts...)
			var s LookupClusterWorkloadMappingResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupClusterWorkloadMappingResultOutput)
}

// A collection of arguments for invoking getClusterWorkloadMapping.
type LookupClusterWorkloadMappingOutputArgs struct {
	// The OCID of the cluster.
	ClusterId pulumi.StringInput `pulumi:"clusterId"`
	// The OCID of the workloadMapping.
	WorkloadMappingId pulumi.StringInput `pulumi:"workloadMappingId"`
}

func (LookupClusterWorkloadMappingOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupClusterWorkloadMappingArgs)(nil)).Elem()
}

// A collection of values returned by getClusterWorkloadMapping.
type LookupClusterWorkloadMappingResultOutput struct{ *pulumi.OutputState }

func (LookupClusterWorkloadMappingResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupClusterWorkloadMappingResult)(nil)).Elem()
}

func (o LookupClusterWorkloadMappingResultOutput) ToLookupClusterWorkloadMappingResultOutput() LookupClusterWorkloadMappingResultOutput {
	return o
}

func (o LookupClusterWorkloadMappingResultOutput) ToLookupClusterWorkloadMappingResultOutputWithContext(ctx context.Context) LookupClusterWorkloadMappingResultOutput {
	return o
}

// The OCID of the cluster.
func (o LookupClusterWorkloadMappingResultOutput) ClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.ClusterId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupClusterWorkloadMappingResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupClusterWorkloadMappingResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The ocid of the workloadMapping.
func (o LookupClusterWorkloadMappingResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the mapped customer compartment.
func (o LookupClusterWorkloadMappingResultOutput) MappedCompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.MappedCompartmentId }).(pulumi.StringOutput)
}

// The OCID of the mapped customer tenancy.
func (o LookupClusterWorkloadMappingResultOutput) MappedTenancyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.MappedTenancyId }).(pulumi.StringOutput)
}

// The namespace of the workloadMapping.
func (o LookupClusterWorkloadMappingResultOutput) Namespace() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.Namespace }).(pulumi.StringOutput)
}

// The state of the workloadMapping.
func (o LookupClusterWorkloadMappingResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.State }).(pulumi.StringOutput)
}

// The time the cluster was created.
func (o LookupClusterWorkloadMappingResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func (o LookupClusterWorkloadMappingResultOutput) WorkloadMappingId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupClusterWorkloadMappingResult) string { return v.WorkloadMappingId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupClusterWorkloadMappingResultOutput{})
}