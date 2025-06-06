// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Masking Policy resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets the details of the specified masking policy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetMaskingPolicy(ctx, &datasafe.GetMaskingPolicyArgs{
//				MaskingPolicyId: testMaskingPolicyOciDataSafeMaskingPolicy.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMaskingPolicy(ctx *pulumi.Context, args *LookupMaskingPolicyArgs, opts ...pulumi.InvokeOption) (*LookupMaskingPolicyResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupMaskingPolicyResult
	err := ctx.Invoke("oci:DataSafe/getMaskingPolicy:getMaskingPolicy", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMaskingPolicy.
type LookupMaskingPolicyArgs struct {
	// The OCID of the masking policy.
	MaskingPolicyId string `pulumi:"maskingPolicyId"`
}

// A collection of values returned by getMaskingPolicy.
type LookupMaskingPolicyResult struct {
	AddMaskingColumnsFromSdmTrigger int `pulumi:"addMaskingColumnsFromSdmTrigger"`
	// The source of masking columns.
	ColumnSources []GetMaskingPolicyColumnSource `pulumi:"columnSources"`
	// The OCID of the compartment that contains the masking policy.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the masking policy.
	Description string `pulumi:"description"`
	// The display name of the masking policy.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags                map[string]string `pulumi:"freeformTags"`
	GenerateHealthReportTrigger int               `pulumi:"generateHealthReportTrigger"`
	// The OCID of the masking policy.
	Id string `pulumi:"id"`
	// Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default. Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive  data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want  to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables  must be dropped before the database is available for unprivileged users.
	IsDropTempTablesEnabled bool `pulumi:"isDropTempTablesEnabled"`
	// Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked  data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking, you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.
	IsRedoLoggingEnabled bool `pulumi:"isRedoLoggingEnabled"`
	// Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics gathering. The masking process gathers statistics on masked database tables after masking completes.
	IsRefreshStatsEnabled bool   `pulumi:"isRefreshStatsEnabled"`
	MaskingPolicyId       string `pulumi:"maskingPolicyId"`
	// Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism), 'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree of parallelism. Parallel execution helps effectively use multiple CPUs and improve masking performance. Refer to the Oracle Database parallel execution framework when choosing an explicit degree of parallelism.
	ParallelDegree string `pulumi:"parallelDegree"`
	// A post-masking script, which can contain SQL and PL/SQL statements. It's executed after the core masking script generated using the masking policy. It's usually used to perform additional transformation or cleanup work after masking.
	PostMaskingScript string `pulumi:"postMaskingScript"`
	// A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before  the core masking script generated using the masking policy. It's usually used to perform any preparation or prerequisite work before masking data.
	PreMaskingScript string `pulumi:"preMaskingScript"`
	// Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),  'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree attribute is used. Use the built-in UTL_RECOMP package to recompile any remaining invalid objects after masking completes.
	Recompile string `pulumi:"recompile"`
	// The current state of the masking policy.
	State string `pulumi:"state"`
	// The date and time the masking policy was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the masking policy was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupMaskingPolicyOutput(ctx *pulumi.Context, args LookupMaskingPolicyOutputArgs, opts ...pulumi.InvokeOption) LookupMaskingPolicyResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupMaskingPolicyResultOutput, error) {
			args := v.(LookupMaskingPolicyArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getMaskingPolicy:getMaskingPolicy", args, LookupMaskingPolicyResultOutput{}, options).(LookupMaskingPolicyResultOutput), nil
		}).(LookupMaskingPolicyResultOutput)
}

// A collection of arguments for invoking getMaskingPolicy.
type LookupMaskingPolicyOutputArgs struct {
	// The OCID of the masking policy.
	MaskingPolicyId pulumi.StringInput `pulumi:"maskingPolicyId"`
}

func (LookupMaskingPolicyOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMaskingPolicyArgs)(nil)).Elem()
}

// A collection of values returned by getMaskingPolicy.
type LookupMaskingPolicyResultOutput struct{ *pulumi.OutputState }

func (LookupMaskingPolicyResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMaskingPolicyResult)(nil)).Elem()
}

func (o LookupMaskingPolicyResultOutput) ToLookupMaskingPolicyResultOutput() LookupMaskingPolicyResultOutput {
	return o
}

func (o LookupMaskingPolicyResultOutput) ToLookupMaskingPolicyResultOutputWithContext(ctx context.Context) LookupMaskingPolicyResultOutput {
	return o
}

func (o LookupMaskingPolicyResultOutput) AddMaskingColumnsFromSdmTrigger() pulumi.IntOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) int { return v.AddMaskingColumnsFromSdmTrigger }).(pulumi.IntOutput)
}

// The source of masking columns.
func (o LookupMaskingPolicyResultOutput) ColumnSources() GetMaskingPolicyColumnSourceArrayOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) []GetMaskingPolicyColumnSource { return v.ColumnSources }).(GetMaskingPolicyColumnSourceArrayOutput)
}

// The OCID of the compartment that contains the masking policy.
func (o LookupMaskingPolicyResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm) Example: `{"Operations.CostCenter": "42"}`
func (o LookupMaskingPolicyResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the masking policy.
func (o LookupMaskingPolicyResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the masking policy.
func (o LookupMaskingPolicyResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o LookupMaskingPolicyResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

func (o LookupMaskingPolicyResultOutput) GenerateHealthReportTrigger() pulumi.IntOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) int { return v.GenerateHealthReportTrigger }).(pulumi.IntOutput)
}

// The OCID of the masking policy.
func (o LookupMaskingPolicyResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates if the temporary tables created during a masking operation should be dropped after masking. It's enabled by default. Set this attribute to false to preserve the temporary tables. Masking creates temporary tables that map the original sensitive  data values to mask values. By default, these temporary tables are dropped after masking. But, in some cases, you may want  to preserve this information to track how masking changed your data. Note that doing so compromises security. These tables  must be dropped before the database is available for unprivileged users.
func (o LookupMaskingPolicyResultOutput) IsDropTempTablesEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) bool { return v.IsDropTempTablesEnabled }).(pulumi.BoolOutput)
}

// Indicates if redo logging is enabled during a masking operation. It's disabled by default. Set this attribute to true to enable redo logging. By default, masking disables redo logging and flashback logging to purge any original unmasked  data from logs. However, in certain circumstances when you only want to test masking, rollback changes, and retry masking, you could enable logging and use a flashback database to retrieve the original unmasked data after it has been masked.
func (o LookupMaskingPolicyResultOutput) IsRedoLoggingEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) bool { return v.IsRedoLoggingEnabled }).(pulumi.BoolOutput)
}

// Indicates if statistics gathering is enabled. It's enabled by default. Set this attribute to false to disable statistics gathering. The masking process gathers statistics on masked database tables after masking completes.
func (o LookupMaskingPolicyResultOutput) IsRefreshStatsEnabled() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) bool { return v.IsRefreshStatsEnabled }).(pulumi.BoolOutput)
}

func (o LookupMaskingPolicyResultOutput) MaskingPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.MaskingPolicyId }).(pulumi.StringOutput)
}

// Specifies options to enable parallel execution when running data masking. Allowed values are 'NONE' (no parallelism), 'DEFAULT' (the Oracle Database computes the optimum degree of parallelism) or an integer value to be used as the degree of parallelism. Parallel execution helps effectively use multiple CPUs and improve masking performance. Refer to the Oracle Database parallel execution framework when choosing an explicit degree of parallelism.
func (o LookupMaskingPolicyResultOutput) ParallelDegree() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.ParallelDegree }).(pulumi.StringOutput)
}

// A post-masking script, which can contain SQL and PL/SQL statements. It's executed after the core masking script generated using the masking policy. It's usually used to perform additional transformation or cleanup work after masking.
func (o LookupMaskingPolicyResultOutput) PostMaskingScript() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.PostMaskingScript }).(pulumi.StringOutput)
}

// A pre-masking script, which can contain SQL and PL/SQL statements. It's executed before  the core masking script generated using the masking policy. It's usually used to perform any preparation or prerequisite work before masking data.
func (o LookupMaskingPolicyResultOutput) PreMaskingScript() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.PreMaskingScript }).(pulumi.StringOutput)
}

// Specifies how to recompile invalid objects post data masking. Allowed values are 'SERIAL' (recompile in serial),  'PARALLEL' (recompile in parallel), 'NONE' (do not recompile). If it's set to PARALLEL, the value of parallelDegree attribute is used. Use the built-in UTL_RECOMP package to recompile any remaining invalid objects after masking completes.
func (o LookupMaskingPolicyResultOutput) Recompile() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.Recompile }).(pulumi.StringOutput)
}

// The current state of the masking policy.
func (o LookupMaskingPolicyResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the masking policy was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupMaskingPolicyResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the masking policy was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339)
func (o LookupMaskingPolicyResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMaskingPolicyResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMaskingPolicyResultOutput{})
}
