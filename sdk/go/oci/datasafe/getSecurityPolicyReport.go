// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Security Policy Report resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a security policy report by the specified OCID of the security policy report resource.
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
//			_, err := datasafe.GetSecurityPolicyReport(ctx, &datasafe.GetSecurityPolicyReportArgs{
//				SecurityPolicyReportId: testSecurityPolicyReportOciDataSafeSecurityPolicyReport.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSecurityPolicyReport(ctx *pulumi.Context, args *GetSecurityPolicyReportArgs, opts ...pulumi.InvokeOption) (*GetSecurityPolicyReportResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSecurityPolicyReportResult
	err := ctx.Invoke("oci:DataSafe/getSecurityPolicyReport:getSecurityPolicyReport", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecurityPolicyReport.
type GetSecurityPolicyReportArgs struct {
	// The OCID of the security policy report resource.
	SecurityPolicyReportId string `pulumi:"securityPolicyReportId"`
}

// A collection of values returned by getSecurityPolicyReport.
type GetSecurityPolicyReportResult struct {
	// The OCID of the compartment that contains the security policy report.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description of the security policy report.
	Description string `pulumi:"description"`
	// The display name of the security policy report.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Details about the current state of the security policy report.
	LifecycleDetails       string `pulumi:"lifecycleDetails"`
	SecurityPolicyReportId string `pulumi:"securityPolicyReportId"`
	// The current state of the security policy report.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The OCID of the of the  target database.
	TargetId string `pulumi:"targetId"`
	// The date and time the security policy report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the security policy report was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
}

func GetSecurityPolicyReportOutput(ctx *pulumi.Context, args GetSecurityPolicyReportOutputArgs, opts ...pulumi.InvokeOption) GetSecurityPolicyReportResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSecurityPolicyReportResultOutput, error) {
			args := v.(GetSecurityPolicyReportArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getSecurityPolicyReport:getSecurityPolicyReport", args, GetSecurityPolicyReportResultOutput{}, options).(GetSecurityPolicyReportResultOutput), nil
		}).(GetSecurityPolicyReportResultOutput)
}

// A collection of arguments for invoking getSecurityPolicyReport.
type GetSecurityPolicyReportOutputArgs struct {
	// The OCID of the security policy report resource.
	SecurityPolicyReportId pulumi.StringInput `pulumi:"securityPolicyReportId"`
}

func (GetSecurityPolicyReportOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityPolicyReportArgs)(nil)).Elem()
}

// A collection of values returned by getSecurityPolicyReport.
type GetSecurityPolicyReportResultOutput struct{ *pulumi.OutputState }

func (GetSecurityPolicyReportResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityPolicyReportResult)(nil)).Elem()
}

func (o GetSecurityPolicyReportResultOutput) ToGetSecurityPolicyReportResultOutput() GetSecurityPolicyReportResultOutput {
	return o
}

func (o GetSecurityPolicyReportResultOutput) ToGetSecurityPolicyReportResultOutputWithContext(ctx context.Context) GetSecurityPolicyReportResultOutput {
	return o
}

// The OCID of the compartment that contains the security policy report.
func (o GetSecurityPolicyReportResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o GetSecurityPolicyReportResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description of the security policy report.
func (o GetSecurityPolicyReportResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.Description }).(pulumi.StringOutput)
}

// The display name of the security policy report.
func (o GetSecurityPolicyReportResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o GetSecurityPolicyReportResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSecurityPolicyReportResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.Id }).(pulumi.StringOutput)
}

// Details about the current state of the security policy report.
func (o GetSecurityPolicyReportResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

func (o GetSecurityPolicyReportResultOutput) SecurityPolicyReportId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.SecurityPolicyReportId }).(pulumi.StringOutput)
}

// The current state of the security policy report.
func (o GetSecurityPolicyReportResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o GetSecurityPolicyReportResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The OCID of the of the  target database.
func (o GetSecurityPolicyReportResultOutput) TargetId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.TargetId }).(pulumi.StringOutput)
}

// The date and time the security policy report was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o GetSecurityPolicyReportResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the security policy report was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o GetSecurityPolicyReportResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityPolicyReportResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecurityPolicyReportResultOutput{})
}
