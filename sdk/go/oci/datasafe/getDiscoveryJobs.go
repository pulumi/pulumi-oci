// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Discovery Jobs in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of incremental discovery jobs based on the specified query parameters.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DataSafe.GetDiscoveryJobs(ctx, &datasafe.GetDiscoveryJobsArgs{
// 			CompartmentId:          _var.Compartment_id,
// 			AccessLevel:            pulumi.StringRef(_var.Discovery_job_access_level),
// 			CompartmentIdInSubtree: pulumi.BoolRef(_var.Discovery_job_compartment_id_in_subtree),
// 			DiscoveryJobId:         pulumi.StringRef(oci_data_safe_discovery_job.Test_discovery_job.Id),
// 			DisplayName:            pulumi.StringRef(_var.Discovery_job_display_name),
// 			SensitiveDataModelId:   pulumi.StringRef(oci_data_safe_sensitive_data_model.Test_sensitive_data_model.Id),
// 			State:                  pulumi.StringRef(_var.Discovery_job_state),
// 			TargetId:               pulumi.StringRef(oci_cloud_guard_target.Test_target.Id),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func LookupDiscoveryJobs(ctx *pulumi.Context, args *LookupDiscoveryJobsArgs, opts ...pulumi.InvokeOption) (*LookupDiscoveryJobsResult, error) {
	var rv LookupDiscoveryJobsResult
	err := ctx.Invoke("oci:DataSafe/getDiscoveryJobs:getDiscoveryJobs", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDiscoveryJobs.
type LookupDiscoveryJobsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool `pulumi:"compartmentIdInSubtree"`
	// A filter to return only the resources that match the specified discovery job OCID.
	DiscoveryJobId *string `pulumi:"discoveryJobId"`
	// A filter to return only resources that match the specified display name.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetDiscoveryJobsFilter `pulumi:"filters"`
	// A filter to return only the resources that match the specified sensitive data model OCID.
	SensitiveDataModelId *string `pulumi:"sensitiveDataModelId"`
	// A filter to return only the resources that match the specified lifecycle state.
	State *string `pulumi:"state"`
	// A filter to return only items related to a specific target OCID.
	TargetId *string `pulumi:"targetId"`
}

// A collection of values returned by getDiscoveryJobs.
type LookupDiscoveryJobsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the compartment that contains the discovery job.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The list of discovery_job_collection.
	DiscoveryJobCollections []GetDiscoveryJobsDiscoveryJobCollection `pulumi:"discoveryJobCollections"`
	DiscoveryJobId          *string                                  `pulumi:"discoveryJobId"`
	// The display name of the discovery job.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetDiscoveryJobsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the sensitive data model associated with the discovery job.
	SensitiveDataModelId *string `pulumi:"sensitiveDataModelId"`
	// The current state of the discovery job.
	State *string `pulumi:"state"`
	// The OCID of the target database associated with the discovery job.
	TargetId *string `pulumi:"targetId"`
}

func LookupDiscoveryJobsOutput(ctx *pulumi.Context, args LookupDiscoveryJobsOutputArgs, opts ...pulumi.InvokeOption) LookupDiscoveryJobsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupDiscoveryJobsResult, error) {
			args := v.(LookupDiscoveryJobsArgs)
			r, err := LookupDiscoveryJobs(ctx, &args, opts...)
			var s LookupDiscoveryJobsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupDiscoveryJobsResultOutput)
}

// A collection of arguments for invoking getDiscoveryJobs.
type LookupDiscoveryJobsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput `pulumi:"compartmentIdInSubtree"`
	// A filter to return only the resources that match the specified discovery job OCID.
	DiscoveryJobId pulumi.StringPtrInput `pulumi:"discoveryJobId"`
	// A filter to return only resources that match the specified display name.
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetDiscoveryJobsFilterArrayInput `pulumi:"filters"`
	// A filter to return only the resources that match the specified sensitive data model OCID.
	SensitiveDataModelId pulumi.StringPtrInput `pulumi:"sensitiveDataModelId"`
	// A filter to return only the resources that match the specified lifecycle state.
	State pulumi.StringPtrInput `pulumi:"state"`
	// A filter to return only items related to a specific target OCID.
	TargetId pulumi.StringPtrInput `pulumi:"targetId"`
}

func (LookupDiscoveryJobsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDiscoveryJobsArgs)(nil)).Elem()
}

// A collection of values returned by getDiscoveryJobs.
type LookupDiscoveryJobsResultOutput struct{ *pulumi.OutputState }

func (LookupDiscoveryJobsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDiscoveryJobsResult)(nil)).Elem()
}

func (o LookupDiscoveryJobsResultOutput) ToLookupDiscoveryJobsResultOutput() LookupDiscoveryJobsResultOutput {
	return o
}

func (o LookupDiscoveryJobsResultOutput) ToLookupDiscoveryJobsResultOutputWithContext(ctx context.Context) LookupDiscoveryJobsResultOutput {
	return o
}

func (o LookupDiscoveryJobsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The OCID of the compartment that contains the discovery job.
func (o LookupDiscoveryJobsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o LookupDiscoveryJobsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// The list of discovery_job_collection.
func (o LookupDiscoveryJobsResultOutput) DiscoveryJobCollections() GetDiscoveryJobsDiscoveryJobCollectionArrayOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) []GetDiscoveryJobsDiscoveryJobCollection {
		return v.DiscoveryJobCollections
	}).(GetDiscoveryJobsDiscoveryJobCollectionArrayOutput)
}

func (o LookupDiscoveryJobsResultOutput) DiscoveryJobId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *string { return v.DiscoveryJobId }).(pulumi.StringPtrOutput)
}

// The display name of the discovery job.
func (o LookupDiscoveryJobsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o LookupDiscoveryJobsResultOutput) Filters() GetDiscoveryJobsFilterArrayOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) []GetDiscoveryJobsFilter { return v.Filters }).(GetDiscoveryJobsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o LookupDiscoveryJobsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the sensitive data model associated with the discovery job.
func (o LookupDiscoveryJobsResultOutput) SensitiveDataModelId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *string { return v.SensitiveDataModelId }).(pulumi.StringPtrOutput)
}

// The current state of the discovery job.
func (o LookupDiscoveryJobsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The OCID of the target database associated with the discovery job.
func (o LookupDiscoveryJobsResultOutput) TargetId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupDiscoveryJobsResult) *string { return v.TargetId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDiscoveryJobsResultOutput{})
}