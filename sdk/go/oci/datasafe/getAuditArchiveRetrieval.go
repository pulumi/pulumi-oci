// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Audit Archive Retrieval resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified archive retreival.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataSafe.GetAuditArchiveRetrieval(ctx, &datasafe.GetAuditArchiveRetrievalArgs{
//				AuditArchiveRetrievalId: oci_data_safe_audit_archive_retrieval.Test_audit_archive_retrieval.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupAuditArchiveRetrieval(ctx *pulumi.Context, args *LookupAuditArchiveRetrievalArgs, opts ...pulumi.InvokeOption) (*LookupAuditArchiveRetrievalResult, error) {
	var rv LookupAuditArchiveRetrievalResult
	err := ctx.Invoke("oci:DataSafe/getAuditArchiveRetrieval:getAuditArchiveRetrieval", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAuditArchiveRetrieval.
type LookupAuditArchiveRetrievalArgs struct {
	// OCID of the archive retrieval.
	AuditArchiveRetrievalId string `pulumi:"auditArchiveRetrievalId"`
}

// A collection of values returned by getAuditArchiveRetrieval.
type LookupAuditArchiveRetrievalResult struct {
	AuditArchiveRetrievalId string `pulumi:"auditArchiveRetrievalId"`
	// Total count of audit events to be retrieved from the archive for the specified date range.
	AuditEventCount string `pulumi:"auditEventCount"`
	// The OCID of the compartment that contains archive retrieval.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Description of the archive retrieval.
	Description string `pulumi:"description"`
	// The display name of the archive retrieval. The name does not have to be unique, and is changeable.
	DisplayName string `pulumi:"displayName"`
	// End month of the archive retrieval, in the format defined by RFC3339.
	EndDate string `pulumi:"endDate"`
	// The Error details of a failed archive retrieval.
	ErrorInfo string `pulumi:"errorInfo"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the archive retrieval.
	Id string `pulumi:"id"`
	// Details about the current state of the archive retrieval.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// Start month of the archive retrieval, in the format defined by RFC3339.
	StartDate string `pulumi:"startDate"`
	// The current state of the archive retrieval.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The OCID of the target associated with the archive retrieval.
	TargetId string `pulumi:"targetId"`
	// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
	TimeCompleted string `pulumi:"timeCompleted"`
	// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
	TimeOfExpiry string `pulumi:"timeOfExpiry"`
	// The date time when archive retrieval was requested, in the format defined by RFC3339.
	TimeRequested string `pulumi:"timeRequested"`
}

func LookupAuditArchiveRetrievalOutput(ctx *pulumi.Context, args LookupAuditArchiveRetrievalOutputArgs, opts ...pulumi.InvokeOption) LookupAuditArchiveRetrievalResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupAuditArchiveRetrievalResult, error) {
			args := v.(LookupAuditArchiveRetrievalArgs)
			r, err := LookupAuditArchiveRetrieval(ctx, &args, opts...)
			var s LookupAuditArchiveRetrievalResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupAuditArchiveRetrievalResultOutput)
}

// A collection of arguments for invoking getAuditArchiveRetrieval.
type LookupAuditArchiveRetrievalOutputArgs struct {
	// OCID of the archive retrieval.
	AuditArchiveRetrievalId pulumi.StringInput `pulumi:"auditArchiveRetrievalId"`
}

func (LookupAuditArchiveRetrievalOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAuditArchiveRetrievalArgs)(nil)).Elem()
}

// A collection of values returned by getAuditArchiveRetrieval.
type LookupAuditArchiveRetrievalResultOutput struct{ *pulumi.OutputState }

func (LookupAuditArchiveRetrievalResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupAuditArchiveRetrievalResult)(nil)).Elem()
}

func (o LookupAuditArchiveRetrievalResultOutput) ToLookupAuditArchiveRetrievalResultOutput() LookupAuditArchiveRetrievalResultOutput {
	return o
}

func (o LookupAuditArchiveRetrievalResultOutput) ToLookupAuditArchiveRetrievalResultOutputWithContext(ctx context.Context) LookupAuditArchiveRetrievalResultOutput {
	return o
}

func (o LookupAuditArchiveRetrievalResultOutput) AuditArchiveRetrievalId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.AuditArchiveRetrievalId }).(pulumi.StringOutput)
}

// Total count of audit events to be retrieved from the archive for the specified date range.
func (o LookupAuditArchiveRetrievalResultOutput) AuditEventCount() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.AuditEventCount }).(pulumi.StringOutput)
}

// The OCID of the compartment that contains archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o LookupAuditArchiveRetrievalResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Description of the archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the archive retrieval. The name does not have to be unique, and is changeable.
func (o LookupAuditArchiveRetrievalResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// End month of the archive retrieval, in the format defined by RFC3339.
func (o LookupAuditArchiveRetrievalResultOutput) EndDate() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.EndDate }).(pulumi.StringOutput)
}

// The Error details of a failed archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) ErrorInfo() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.ErrorInfo }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupAuditArchiveRetrievalResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.Id }).(pulumi.StringOutput)
}

// Details about the current state of the archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Start month of the archive retrieval, in the format defined by RFC3339.
func (o LookupAuditArchiveRetrievalResultOutput) StartDate() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.StartDate }).(pulumi.StringOutput)
}

// The current state of the archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupAuditArchiveRetrievalResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The OCID of the target associated with the archive retrieval.
func (o LookupAuditArchiveRetrievalResultOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.TargetId }).(pulumi.StringOutput)
}

// The date time when archive retrieval request was fulfilled, in the format defined by RFC3339.
func (o LookupAuditArchiveRetrievalResultOutput) TimeCompleted() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.TimeCompleted }).(pulumi.StringOutput)
}

// The date time when retrieved archive data will be deleted from Data Safe and unloaded back into archival.
func (o LookupAuditArchiveRetrievalResultOutput) TimeOfExpiry() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.TimeOfExpiry }).(pulumi.StringOutput)
}

// The date time when archive retrieval was requested, in the format defined by RFC3339.
func (o LookupAuditArchiveRetrievalResultOutput) TimeRequested() pulumi.StringOutput {
	return o.ApplyT(func(v LookupAuditArchiveRetrievalResult) string { return v.TimeRequested }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupAuditArchiveRetrievalResultOutput{})
}