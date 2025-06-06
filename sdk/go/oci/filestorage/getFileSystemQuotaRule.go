// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific File System Quota Rule resource in Oracle Cloud Infrastructure File Storage service.
//
// Get an FS level, user or group quota rule given the `fileSystemId` and `quotaRuleId` parameters.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/filestorage"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := filestorage.GetFileSystemQuotaRule(ctx, &filestorage.GetFileSystemQuotaRuleArgs{
//				FileSystemId: testFileSystem.Id,
//				QuotaRuleId:  pulumi.StringRef(testRule.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupFileSystemQuotaRule(ctx *pulumi.Context, args *LookupFileSystemQuotaRuleArgs, opts ...pulumi.InvokeOption) (*LookupFileSystemQuotaRuleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupFileSystemQuotaRuleResult
	err := ctx.Invoke("oci:FileStorage/getFileSystemQuotaRule:getFileSystemQuotaRule", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFileSystemQuotaRule.
type LookupFileSystemQuotaRuleArgs struct {
	AreViolatorsOnly *string `pulumi:"areViolatorsOnly"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId string `pulumi:"fileSystemId"`
	// The identifier of the quota rule. It is the base64 encoded string of the tuple <principalId, principalType, isHardQuota>.
	QuotaRuleId *string `pulumi:"quotaRuleId"`
}

// A collection of values returned by getFileSystemQuotaRule.
type LookupFileSystemQuotaRuleResult struct {
	AreViolatorsOnly *string `pulumi:"areViolatorsOnly"`
	// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
	DisplayName string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file System.
	FileSystemId string `pulumi:"fileSystemId"`
	// The identifier of the quota rule. It is the base64 encoded string of the tuple <principalId, principalType, isHardQuota>.
	Id string `pulumi:"id"`
	// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is false, the quota rule will be enforced so the usage cannot exceed the hard quota limit. If `isHardQuota` is true, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
	IsHardQuota bool `pulumi:"isHardQuota"`
	// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
	PrincipalId int `pulumi:"principalId"`
	// The type of the owner of this quota rule and usage.
	PrincipalType string `pulumi:"principalType"`
	// The value of the quota rule. The unit is Gigabyte.
	QuotaLimitInGigabytes int     `pulumi:"quotaLimitInGigabytes"`
	QuotaRuleId           *string `pulumi:"quotaRuleId"`
	// The date and time the quota rule was started, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the quota rule was last updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupFileSystemQuotaRuleOutput(ctx *pulumi.Context, args LookupFileSystemQuotaRuleOutputArgs, opts ...pulumi.InvokeOption) LookupFileSystemQuotaRuleResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupFileSystemQuotaRuleResultOutput, error) {
			args := v.(LookupFileSystemQuotaRuleArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:FileStorage/getFileSystemQuotaRule:getFileSystemQuotaRule", args, LookupFileSystemQuotaRuleResultOutput{}, options).(LookupFileSystemQuotaRuleResultOutput), nil
		}).(LookupFileSystemQuotaRuleResultOutput)
}

// A collection of arguments for invoking getFileSystemQuotaRule.
type LookupFileSystemQuotaRuleOutputArgs struct {
	AreViolatorsOnly pulumi.StringPtrInput `pulumi:"areViolatorsOnly"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId pulumi.StringInput `pulumi:"fileSystemId"`
	// The identifier of the quota rule. It is the base64 encoded string of the tuple <principalId, principalType, isHardQuota>.
	QuotaRuleId pulumi.StringPtrInput `pulumi:"quotaRuleId"`
}

func (LookupFileSystemQuotaRuleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupFileSystemQuotaRuleArgs)(nil)).Elem()
}

// A collection of values returned by getFileSystemQuotaRule.
type LookupFileSystemQuotaRuleResultOutput struct{ *pulumi.OutputState }

func (LookupFileSystemQuotaRuleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupFileSystemQuotaRuleResult)(nil)).Elem()
}

func (o LookupFileSystemQuotaRuleResultOutput) ToLookupFileSystemQuotaRuleResultOutput() LookupFileSystemQuotaRuleResultOutput {
	return o
}

func (o LookupFileSystemQuotaRuleResultOutput) ToLookupFileSystemQuotaRuleResultOutputWithContext(ctx context.Context) LookupFileSystemQuotaRuleResultOutput {
	return o
}

func (o LookupFileSystemQuotaRuleResultOutput) AreViolatorsOnly() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) *string { return v.AreViolatorsOnly }).(pulumi.StringPtrOutput)
}

// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
func (o LookupFileSystemQuotaRuleResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file System.
func (o LookupFileSystemQuotaRuleResultOutput) FileSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) string { return v.FileSystemId }).(pulumi.StringOutput)
}

// The identifier of the quota rule. It is the base64 encoded string of the tuple <principalId, principalType, isHardQuota>.
func (o LookupFileSystemQuotaRuleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) string { return v.Id }).(pulumi.StringOutput)
}

// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is false, the quota rule will be enforced so the usage cannot exceed the hard quota limit. If `isHardQuota` is true, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
func (o LookupFileSystemQuotaRuleResultOutput) IsHardQuota() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) bool { return v.IsHardQuota }).(pulumi.BoolOutput)
}

// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
func (o LookupFileSystemQuotaRuleResultOutput) PrincipalId() pulumi.IntOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) int { return v.PrincipalId }).(pulumi.IntOutput)
}

// The type of the owner of this quota rule and usage.
func (o LookupFileSystemQuotaRuleResultOutput) PrincipalType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) string { return v.PrincipalType }).(pulumi.StringOutput)
}

// The value of the quota rule. The unit is Gigabyte.
func (o LookupFileSystemQuotaRuleResultOutput) QuotaLimitInGigabytes() pulumi.IntOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) int { return v.QuotaLimitInGigabytes }).(pulumi.IntOutput)
}

func (o LookupFileSystemQuotaRuleResultOutput) QuotaRuleId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) *string { return v.QuotaRuleId }).(pulumi.StringPtrOutput)
}

// The date and time the quota rule was started, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o LookupFileSystemQuotaRuleResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the quota rule was last updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o LookupFileSystemQuotaRuleResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupFileSystemQuotaRuleResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupFileSystemQuotaRuleResultOutput{})
}
